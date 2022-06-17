#define _GNU_SOURCE
#include "xdp_runner.h"

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <linux/kernel.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/perf_event.h>
#include <linux/btf.h>
#include <sys/syscall.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include "kmod/rex.h"

static int xdp_prog_fd = -1;
static int attr_map_fd = -1;
static int handler_prog_fd = -1;
static int event_map_fd = -1;

enum { log_buf_size = 16 * 1024 };
static char log_buf[log_buf_size];

#define pr_warn(fmt, ...)	\
do {				\
	fprintf(stderr, "xdpscan: " fmt, ##__VA_ARGS__);	\
} while (0)

#define ARRAY_LENGTH(a) (sizeof(a)/sizeof((a)[0]))

static
__s64 determine_kfunc_id(const char *mod, const char* symb)
{
	struct bpf_btf_info info;
	struct btf *btf_vmlinux, *btf_rex;
	char name[64];
	__u32 id = 0, len;
	__s32 func;
	int btf_fd, err;

	btf_vmlinux = btf__load_vmlinux_btf();
	err = libbpf_get_error(btf_vmlinux);
	if (err) {
		pr_warn("Cannot load vmlinux BTF: %s\n", strerror(-err));
		return -1;
	}

	btf_rex = btf__load_module_btf(mod, btf_vmlinux);
	err = libbpf_get_error(btf_rex);
	if (err) {
		pr_warn("Cannot load %s BTF: %s\n", mod, strerror(-err));
		btf__free(btf_vmlinux);
		return -1;
	}

	func = btf__find_by_name_kind(btf_rex, symb, BTF_KIND_FUNC);
	btf__free(btf_vmlinux);
	btf__free(btf_rex);
	if (func < 0) {
		pr_warn("Cannot find '%s' func in module '%s'", symb, mod);
		return -1;
	}

	while (true) {
		err = bpf_btf_get_next_id(id, &id);
		if (err && errno == ENOENT) {
			pr_warn("failed to find module's BTF id\n");
			return err;
		} if (err) {
			err = -errno;
			pr_warn("failed to iterate BTF objects: %d\n", err);
			return err;
		}

		btf_fd = bpf_btf_get_fd_by_id(id);
		if (btf_fd < 0) {
			pr_warn("cannot get BTF fd: %s", strerror(-btf_fd));
		}

		len = sizeof(info);
		memset(&info, 0, sizeof(info));
		info.name = (__u64) (unsigned long) name;
		info.name_len = sizeof(name);

		err = bpf_obj_get_info_by_fd(btf_fd, &info, &len);
		if (err) {
			pr_warn("failed to get BTF object #%d info: %d\n", id, err);
			close(btf_fd);
			continue;
		}

		if (strcmp(name, REX_MODULE) == 0)
			break;

		close(btf_fd);
	}

	return ((__u64)btf_fd << 32) | func;
}

#define BPF_CALL_KFUNC(BTF_ID, FUNC_ID)				\
	((struct bpf_insn) {					\
		.code  = BPF_JMP | BPF_CALL,			\
		.dst_reg = 0,					\
		.src_reg = BPF_PSEUDO_KFUNC_CALL,		\
		.off   = BTF_ID,				\
		.imm   = FUNC_ID })

#ifndef BPF_ALU64_REG
#define BPF_ALU64_REG(OP, DST, SRC)				\
	((struct bpf_insn) {					\
		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\
		.dst_reg = DST,					\
		.src_reg = SRC,					\
		.off   = 0,					\
		.imm   = 0 })
#endif

static
int init_xdp_prog(void)
{
	int fd_array[] = { -1, -1 };
	static const int btf_off = 1;
	__s64 kfunc;
	int ret;

	kfunc = determine_kfunc_id(REX_MODULE, "bpf_xdp_scan_bytes");
	fd_array[btf_off] = kfunc >> 32u;

	if (kfunc < 0)
		return kfunc;

	ret  = bpf_map_create(BPF_MAP_TYPE_ARRAY, "scan_attr_inout",
			      sizeof(__u32), sizeof(struct rex_scan_attr),
			      1, NULL);
	if (ret < 0) {
		pr_warn("failed to create map: %s\n", strerror(-ret));
		return ret;
	}

	attr_map_fd = ret;

	struct bpf_insn xdp_prog[] = {
		BPF_MOV64_REG(BPF_REG_9, BPF_REG_1),
		BPF_LD_MAP_FD(BPF_REG_1, attr_map_fd),
		/* key = 0 */
		BPF_ST_MEM(BPF_W, BPF_REG_10, -0x4, 0),
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_6, -0x4),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
		BPF_EMIT_CALL(BPF_FUNC_map_lookup_elem),
		/* r8 = &scan_attr */
		BPF_MOV64_REG(BPF_REG_8, BPF_REG_0),
		BPF_MOV64_IMM(BPF_REG_0, -EFAULT),
		BPF_JMP_IMM(BPF_JEQ, BPF_REG_8, 0, 16),
		/* xdp->data */
		BPF_LDX_MEM(BPF_W, BPF_REG_1, BPF_REG_9, 0),
		/* xdp->data_end */
		BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_9, 4),
		/* packet length */
		BPF_ALU64_REG(BPF_SUB, BPF_REG_3, BPF_REG_1),
		/* struct xdp_md *xdp */
		BPF_MOV64_REG(BPF_REG_1, BPF_REG_9),
		/* start offset */
		BPF_MOV64_IMM(BPF_REG_2, 0),
		/* &scan_attr */
		BPF_MOV64_REG(BPF_REG_4, BPF_REG_8),
		BPF_CALL_KFUNC(btf_off, (__u32) kfunc),
		/* error ? */
		BPF_MOV64_REG(BPF_REG_7, BPF_REG_0),
		BPF_JMP_IMM(BPF_JLT, BPF_REG_0, 0, 7),
		BPF_LD_MAP_FD(BPF_REG_1, attr_map_fd),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_6),
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_8),
		BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
		BPF_EMIT_CALL(BPF_FUNC_map_update_elem),
		BPF_MOV64_REG(BPF_REG_0, BPF_REG_7),
		BPF_EXIT_INSN(),
	};

	LIBBPF_OPTS(bpf_prog_load_opts, prog_opts,
		.log_buf = log_buf,
		.log_size = log_buf_size,
		.fd_array = fd_array,
	);
	ret = bpf_prog_load(BPF_PROG_TYPE_XDP, NULL, "Dual BSD/GPL",
			    xdp_prog, ARRAY_LENGTH(xdp_prog), &prog_opts);
	if (ret < 0) {
		pr_warn("failed to load rex program (%d):\n%s", errno, log_buf);
		close(attr_map_fd);
		close(fd_array[btf_off]);
		return ret;
	}

	xdp_prog_fd = ret;
	close(fd_array[btf_off]);
	return 0;
}

/*
 * this function is expected to parse integer in the range of [0, 2^31-1] from
 * given file using scanf format string fmt. If actual parsed value is
 * negative, the result might be indistinguishable from error
 */
static
int parse_uint_from_file(const char *file, const char *fmt)
{
	int err, ret;
	FILE *f;

	f = fopen(file, "r");
	if (!f) {
		err = -errno;
		pr_warn("failed to open '%s': %s\n", file,
			strerror(-err));
		return err;
	}
	err = fscanf(f, fmt, &ret);
	if (err != 1) {
		err = err == EOF ? -EIO : -errno;
		pr_warn("failed to parse '%s': %s\n", file,
			strerror(-err));
		ret = err;
	}
	fclose(f);
	return ret;
}

/* based on libbpf */
static
int determine_tracepoint_id(const char *tp_category,
				   const char *tp_name)
{
	char file[PATH_MAX];
	int ret;

	ret = snprintf(file, sizeof(file),
		       "/sys/kernel/debug/tracing/events/%s/%s/id",
		       tp_category, tp_name);
	if (ret < 0)
		return -errno;
	if (ret >= PATH_MAX) {
		pr_warn("tracepoint %s/%s path is too long\n",
			tp_category, tp_name);
		return -E2BIG;
	}
	return parse_uint_from_file(file, "%d\n");
}

/* based on libbpf */
static
int perf_event_open_tracepoint(const char *tp_category,
				      const char *tp_name)
{
	struct perf_event_attr attr = {};
	int tp_id, pfd, err;

	tp_id = determine_tracepoint_id(tp_category, tp_name);
	if (tp_id < 0) {
		pr_warn("failed to determine tracepoint '%s/%s' perf event ID: %s\n",
			tp_category, tp_name,
			strerror(-tp_id));
		return tp_id;
	}

	attr.type = PERF_TYPE_TRACEPOINT;
	attr.size = sizeof(attr);
	attr.config = tp_id;

	pfd = syscall(__NR_perf_event_open, &attr, -1 /* pid */, 0 /* cpu */,
		      -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
	if (pfd < 0) {
		err = -errno;
		pr_warn("tracepoint '%s/%s' perf_event_open() failed: %s\n",
			tp_category, tp_name,
			strerror(-err));
		return err;
	}
	return pfd;
}

/* /sys/kernel/debug/tracing/events/rex/rex_match/format */
struct rex_match_args {
	__u64 unused1;
	__u32 database_id;
	__u32 event_index;
	struct rex_event event;
};

static
int init_handler_prog(__u32 max_entries)
{
	int ret;

	ret = bpf_map_create(BPF_MAP_TYPE_ARRAY, "record_cb_out",
			     sizeof(__u32), sizeof(struct rex_event),
			     max_entries, NULL);
	if (ret < 0) {
		pr_warn("failed to create map: %s\n", strerror(-ret));
		return ret;
	}

	event_map_fd = ret;

	struct bpf_insn handler_prog[] = {
		/* return 0 if database_id != REX_TEST_ID */
		BPF_MOV64_IMM(BPF_REG_0, 0),
		/* r2 = args->database_id */
		BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
			    offsetof(struct rex_match_args, database_id)),
		/* if (r2 != REX_TEST_ID) */
		BPF_JMP32_IMM(BPF_JNE, BPF_REG_2, REX_TEST_ID, 18),
		/* r2 = stack_ptr to args->event_index */
		BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_1,
			    offsetof(struct rex_match_args, event_index)),
		BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -0x24),
		BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x24),
		/* r3 = stack_ptr to args->event */
		BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1,
			    offsetof(struct rex_match_args, event)+0x00),
		BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_1,
			    offsetof(struct rex_match_args, event)+0x08),
		BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_1,
			    offsetof(struct rex_match_args, event)+0x10),
		BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_1,
			    offsetof(struct rex_match_args, event)+0x18),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -0x20),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, -0x18),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_8, -0x10),
		BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_9, -0x08),
		BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
		BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x20),
		/* call bpf_map_update_elem() */
		BPF_LD_MAP_FD(BPF_REG_1, event_map_fd),
		BPF_MOV64_IMM(BPF_REG_4, BPF_ANY),
		BPF_EMIT_CALL(BPF_FUNC_map_update_elem),
		/* the jumps are to this instruction */
		BPF_EXIT_INSN(),
	};

	LIBBPF_OPTS(bpf_prog_load_opts, opts,
		.log_buf = log_buf,
		.log_size = log_buf_size,
	);

	ret = bpf_prog_load(BPF_PROG_TYPE_TRACEPOINT, NULL, "Dual BSD/GPL",
			    handler_prog, ARRAY_LENGTH(handler_prog), &opts);
	if (ret < 0) {
		pr_warn("failed to load match handler:\n%s", log_buf);
		return ret;
	}

	handler_prog_fd = ret;

	int pfd = perf_event_open_tracepoint("rex", "rex_match");
	if (pfd < 0)
		return pfd;

	int link_fd = bpf_link_create(handler_prog_fd, pfd, BPF_PERF_EVENT, NULL);
	if (link_fd < 0) {
		pr_warn("failed to create map: %s\n", strerror(-ret));
		return link_fd;
	}

	return 0;
}

static
int rex_apply_handler(__u32 nr_events, match_event_handler on_event,
		      void* context)
{
	struct rex_event ev;
	int ret;

	for (size_t k = 0; k < nr_events; ++k) {
		ret = bpf_map_lookup_elem(event_map_fd, &k, &ev);
		if (ret) {
			pr_warn("failed to lookup match %zu: %s\n", k,
				strerror(-ret));
			return ret;
		}

		on_event(ev.expression, ev.from, ev.to, ev.flags, context);
	}

	return 0;
}


int rex_scan_init(void)
{
	int ret = 0;
	ret = ret ?: init_xdp_prog();
	ret = ret ?: init_handler_prog(4096);
	return ret;
}

hs_error_t rex_test_run(const char *data, __u32 len, __u32 handler_flags,
			match_event_handler on_event, void *context)
{
	struct rex_scan_attr scan_attr = {
		.database_id = REX_TEST_ID,
		.handler_flags = handler_flags,
		.nr_events = 0,
		.last_event = {},
	};

	LIBBPF_OPTS(bpf_test_run_opts, run_opts,
		.repeat		= 1,
		.data_in	= data,
		.data_size_in	= len,
	);

	__u32 out_k = 0;
	int err = 0;

	err = bpf_map_update_elem(attr_map_fd, &out_k, &scan_attr, BPF_ANY);
	if (err < 0) {
		pr_warn("failed to write rex attributes: %s\n", strerror(-err));
		return HS_UNKNOWN_ERROR;
	}

	err = bpf_prog_test_run_opts(xdp_prog_fd, &run_opts);
	if (err < 0) {
		pr_warn("bpf test run failed: %s\n", strerror(-err));
		return HS_UNKNOWN_ERROR;
	}

	err = bpf_map_lookup_elem(attr_map_fd, &out_k, &scan_attr);
	if (err < 0) {
		pr_warn("failed to read rex attributes: %s\n", strerror(-err));
		return HS_UNKNOWN_ERROR;
	}

	err = rex_apply_handler(scan_attr.nr_events, on_event, context);
	if (err < 0)
		return HS_UNKNOWN_ERROR;

	switch (run_opts.retval) {
	case 0:
		return HS_SUCCESS;
	case 1:
		return HS_SCAN_TERMINATED;
	case -ENOEXEC:
		return HS_DB_MODE_ERROR;
	default:
		return HS_UNKNOWN_ERROR;
	}
}
