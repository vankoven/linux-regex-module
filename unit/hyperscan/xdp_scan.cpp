#include <fstream>
#include <algorithm>
#include <gtest/gtest.h>
#include "kmod/rex.h"
#include "allocator.h"
#include "hs_runtime.h"
#include "xdp_runner.h"
#include "test_util.h"

static bool blockScanUsed = false;

extern "C" {

/* Wrap GTEST_SKIP macro into void routine. */
static
void gtest_skip(const char* reason)
{
    GTEST_SKIP() << reason;
}

hs_error_t HS_CDECL
__real_hs_scan(const hs_database_t *db, const char *data, unsigned length, unsigned int flags,
               hs_scratch_t *scratch, match_event_handler onEvent,
               void *context);

hs_error_t HS_CDECL
__wrap_hs_scan(const hs_database_t *db, const char *data, unsigned length,
               unsigned flags, hs_scratch_t *scratch,
               match_event_handler onEvent, void *context)
{
    const testing::TestInfo* const test_info =
        testing::UnitTest::GetInstance()->current_test_info();

    char *regex;
    size_t regex_len, scratch_size;
    __u32 handler_flags = 0;

    blockScanUsed = true;

    if (hs_scratch_size(scratch, &scratch_size)) {
        gtest_skip("Broken scratch");
        goto passthrough;
    }

    if (length > 3520 || scratch_size > (32u << 10)) {
        gtest_skip("Too large for XDP");
        goto passthrough;
    }

    if (!data) {
        gtest_skip("Empty text");
        goto passthrough;
    }

    if (hs_serialize_database(db, &regex, &regex_len) != HS_SUCCESS) {
        gtest_skip("Broken database");
        goto passthrough;
    }

    if (onEvent == terminate_cb)
        handler_flags |= REX_SINGLE_SHOT;
    else if (onEvent == record_cb) {
        CallBackContext *c = (CallBackContext *)context;
        if (c->halt)
            handler_flags |= REX_SINGLE_SHOT;
    }

    {
        std::string cfg_path = test_info->test_case_name();
        cfg_path += '.';
        cfg_path += test_info->name();
        std::replace(cfg_path.begin(), cfg_path.end(), '/', ':');
        cfg_path = std::string("/sys/kernel/config/rex/") + cfg_path;

        GTEST_CHECK_(!mkdir(cfg_path.c_str(), 0644))
            << "cfg_path: " << cfg_path;

        /* upload database to the kernel */
        std::ofstream dbf(cfg_path+"/database", std::ios::binary);
        dbf.write(regex, regex_len);
        free(regex);
        dbf.close();
        GTEST_CHECK_(!!dbf);

        /* check if last write fail */
        std::ifstream epochf(cfg_path+"/epoch", std::ios::binary);
        unsigned epoch;
        epochf >> epoch;
        epochf.close();
        GTEST_CHECK_(!!epochf && epoch <= 1);

        if (epoch == 0) {
            GTEST_CHECK_(!rmdir(cfg_path.c_str()));
            return HS_INVALID;
        }

        /* rewrite database id */
        std::ofstream idf(cfg_path+"/id", std::ios::binary);
        const char *rex_test_id = GTEST_STRINGIFY_(REX_TEST_ID);
        idf.write(rex_test_id, strlen(rex_test_id));
        idf.close();
        GTEST_CHECK_(!!idf);

        hs_error_t retval = rex_test_run(data, length, handler_flags, onEvent, context);
        GTEST_CHECK_(!rmdir(cfg_path.c_str()));
        return retval;
    }

passthrough:
    return __real_hs_scan(db, data, length, flags, scratch, onEvent, context);
}

} // extern "C"

class EventListener : public ::testing::TestEventListener {
protected:
    void OnTestProgramStart(const ::testing::UnitTest&) override {}
    void OnTestIterationStart(const ::testing::UnitTest&, int) override {}
    void OnEnvironmentsSetUpStart(const ::testing::UnitTest&) override {}
    void OnEnvironmentsSetUpEnd(const ::testing::UnitTest&) override {}
#ifndef GTEST_REMOVE_LEGACY_TEST_CASEAPI_
    void OnTestCaseStart(const ::testing::TestCase&) override {}
#endif  // GTEST_REMOVE_LEGACY_TEST_CASEAPI_
    void OnTestStart(const ::testing::TestInfo& /*test_info*/) override {
        blockScanUsed = false;
    }
    void OnTestPartResult(const ::testing::TestPartResult&) override {}
    void OnTestEnd(const ::testing::TestInfo& /*test_info*/) override {
        if (!blockScanUsed)
            GTEST_SKIP() << "hs_scan() wasn't used";
    }
#ifndef GTEST_REMOVE_LEGACY_TEST_CASEAPI_
    void OnTestCaseEnd(const ::testing::TestCase&) override {}
#endif  // GTEST_REMOVE_LEGACY_TEST_CASEAPI_
    void OnEnvironmentsTearDownStart(const ::testing::UnitTest&) override {}
    void OnEnvironmentsTearDownEnd(const ::testing::UnitTest&) override {}
    void OnTestIterationEnd(const ::testing::UnitTest&, int) override {}
    void OnTestProgramEnd(const ::testing::UnitTest&) override {}
};

// Driver: run all the tests (defined in other source files in this directory)
int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);

    if (rex_scan_init())
        return 1;

    testing::UnitTest::GetInstance()->listeners()
        .Append(new EventListener());

    return RUN_ALL_TESTS();
}
