#ifndef XDP_UNIT_RUNNER_H_
#define XDP_UNIT_RUNNER_H_

#include <linux/types.h>
#include "hs_runtime.h"

#define REX_TEST_ID 25489
#define REX_MODULE "xdp_rex"

#ifdef __cplusplus
extern "C" {
#endif

int rex_scan_init(void);

int rex_test_run(const char *data, __u32 len, __u32 handler_flags,
		 match_event_handler on_event, void *context);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // XDP_UNIT_RUNNER_H_
