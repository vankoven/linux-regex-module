// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/init.h>
#include <linux/module.h>
#include <linux/configfs.h>
#include <linux/types.h>
#include <linux/printk.h>
#include <linux/filter.h>
#include <linux/idr.h>
#include <linux/cpumask.h>

#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

#include "allocator.h"
#include "hs_runtime.h"
#include "database.h"
#include "scratch.h"
#include "nfa/nfa_api_queue.h"
#include "rose/rose_internal.h"

#define DATABASE_MAX_SIZE 128*PAGE_SIZE

struct rex_item {
	struct config_item cfg;

	int id;

	atomic_t bytes_scanned;
	atomic_t use_count;

	hs_database_t __rcu *database;
	hs_scratch_t __rcu *__percpu *scratch;
};

DEFINE_IDR(rex_item_idr);

static int rex_match_handler(unsigned int id,
			     unsigned long long from, unsigned long long to,
			     unsigned int flags, void *ctx)
{
	*(int*)ctx = id;
	return 1; /* cease matching */
}

int xdp_rex_match(u32 rex_id, const void *haystack, u32 len)
{
	struct rex_item *rex;
	hs_database_t *db;
	hs_scratch_t *scratch;
	int match = -ESRCH;

	rcu_read_lock();

	if (!likely(rex = idr_find(&rex_item_idr, rex_id)))
		return -EBADF;

	db = rcu_dereference(rex->database);
	scratch = *this_cpu_ptr(rcu_dereference(rex->scratch));

	if (likely(db)) {
	    pr_debug("hs_scan %u bytes\n", len);
	    atomic_add(len, &rex->bytes_scanned);
	    atomic_inc(&rex->use_count);

	    kernel_fpu_begin();
	    hs_scan(db, haystack, len, 0, scratch,
		    rex_match_handler, &match);
	    kernel_fpu_end();
	}

	rcu_read_unlock();
	return match;
}

EXPORT_SYMBOL(xdp_rex_match);

BTF_SET_START(xdp_rex_kfunc_ids)
BTF_ID(func, xdp_rex_match)
BTF_SET_END(xdp_rex_kfunc_ids)
static DEFINE_KFUNC_BTF_ID_SET(&xdp_rex_kfunc_ids, xdp_rex_kfunc_btf_set);

static ssize_t rex_database_read(struct config_item *cfg,
				 void *data, size_t size)
{
	struct rex_item *rex = container_of(cfg, struct rex_item, cfg);
	hs_database_t *db;
	char *bytes = data;
	ssize_t ret;

	rcu_read_lock();

	db = rcu_dereference(rex->database);
	if (!bytes) {
		if (hs_database_size(db, &size) != HS_SUCCESS)
			ret = -EIO;
		else
			ret = size;
	} else {
		if (hs_serialize_database(db, &bytes, NULL) != HS_SUCCESS)
			ret = -EIO;
		else
			ret = size;
	}

	rcu_read_unlock();
	return ret;
}

static void rex_database_reset(struct rex_item *rex, hs_database_t __rcu *db,
			       hs_scratch_t __rcu *__percpu *scratch)
{
	int cpu;

	db = xchg(&rex->database, db);
	scratch = xchg(&rex->scratch, scratch);

	synchronize_rcu();

	if (scratch) {
	    for_each_possible_cpu(cpu)
		    hs_free_scratch(*per_cpu_ptr(scratch, cpu));
	    free_percpu(scratch);
	}

	hs_free_database(db);
}

static ssize_t rex_database_write(struct config_item *cfg,
				  const void *data, size_t size)
{
	struct rex_item *rex = container_of(cfg, struct rex_item, cfg);

	hs_database_t *database = NULL;
	hs_scratch_t *proto = NULL;
	hs_scratch_t *__percpu *scratch;
	int cpu;

	if (hs_deserialize_database(data, size, &database) != HS_SUCCESS)
		return -EINVAL;

	if (hs_alloc_scratch(database, &proto) != HS_SUCCESS) {
		hs_free_database(database);
		return -ENOMEM;
	}

	scratch = alloc_percpu(hs_scratch_t*);
	if (!scratch) {
		hs_free_database(database);
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu) {
		hs_scratch_t **dst = per_cpu_ptr(scratch, cpu);
		if (hs_clone_scratch(proto, dst) != HS_SUCCESS)
			break;
	}
	hs_free_scratch(proto);

	if (cpu < nr_cpu_ids) {
		for_each_possible_cpu(cpu)
			hs_free_scratch(*per_cpu_ptr(scratch, cpu));
		free_percpu(scratch);
		hs_free_database(database);
		return -ENOMEM;
	}

	rex_database_reset(rex, database, scratch);
	return size;
}

static ssize_t rex_info_show(struct config_item *cfg, char *str)
{
	struct rex_item *rex = container_of(cfg, struct rex_item, cfg);
	hs_database_t *db;
	hs_scratch_t *s;
	char *info;
	int ret = 0;

	rcu_read_lock();

	db = rcu_dereference(rex->database);
	s = *this_cpu_ptr(rcu_dereference(rex->scratch));

	if (hs_database_info(rex->database, &info) != HS_SUCCESS) {
		rcu_read_unlock();
		return -EIO;
	}

	ret += sysfs_emit_at(str, ret, "%s\n", info);
	hs_misc_free(info);

	ret += sysfs_emit_at(str, ret, "Scratch space required : %u bytes\n", s->scratchSize);
	ret += sysfs_emit_at(str, ret, "  hs_scratch structure : %zu bytes\n", sizeof(*s));
	ret += sysfs_emit_at(str, ret, "    tctxt structure    : %zu bytes\n", sizeof(s->tctxt));
	ret += sysfs_emit_at(str, ret, "  queues               : %zu bytes\n",
			     s->queueCount * sizeof(struct mq));
	ret += sysfs_emit_at(str, ret, "  bStateSize           : %u bytes\n", s->bStateSize);
	ret += sysfs_emit_at(str, ret, "  active queue array   : %u bytes\n", s->activeQueueArraySize);
	ret += sysfs_emit_at(str, ret, "  qmpq                 : %zu bytes\n",
		s->queueCount * sizeof(struct queue_match));
	ret += sysfs_emit_at(str, ret, "  delay info           : %u bytes\n",
			     s->delay_fatbit_size * DELAY_SLOT_COUNT);

	rcu_read_unlock();
	return ret;
}

static ssize_t rex_id_show(struct config_item *cfg, char* str)
{
	struct rex_item *rex = container_of(cfg, struct rex_item, cfg);
	return sysfs_emit(str, "%d\n", rex->id);
}

static ssize_t rex_stats_show(struct config_item *cfg, char* str)
{
	struct rex_item *rex = container_of(cfg, struct rex_item, cfg);
	int len = 0;

	len += sysfs_emit_at(str, len, "bytes_scanned: %d\n",
			     atomic_read(&rex->bytes_scanned));
	len += sysfs_emit_at(str, len, "use_count: %d\n",
			     atomic_read(&rex->use_count));
	return len;
}

CONFIGFS_ATTR_RO(rex_, id);
CONFIGFS_ATTR_RO(rex_, info);
CONFIGFS_ATTR_RO(rex_, stats);

static struct configfs_attribute *rex_attrs[] = {
	&rex_attr_id,
	&rex_attr_info,
	&rex_attr_stats,
	NULL
};

CONFIGFS_BIN_ATTR(rex_, database, NULL, DATABASE_MAX_SIZE);

static struct configfs_bin_attribute *rex_bin_attrs[] = {
	&rex_attr_database,
	NULL,
};

static const struct config_item_type rex_type = {
	.ct_owner	= THIS_MODULE,
	.ct_attrs	= rex_attrs,
	.ct_bin_attrs	= rex_bin_attrs,
};

static struct config_item *rex_make_item(struct config_group *group,
					 const char *name)
{
	struct rex_item *rex;

	rex = kzalloc(sizeof(*rex), GFP_KERNEL);
	if (!rex)
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&rex->cfg, name, &rex_type);

	rex->id = idr_alloc(&rex_item_idr, rex, 0, 0, GFP_KERNEL);
	if (rex->id < 0) {
		kfree(rex);
		return ERR_PTR(rex->id);
	}

	return &rex->cfg;
}

static void rex_drop_item(struct config_group *group,
			  struct config_item *cfg)
{
	struct rex_item *rex = container_of(cfg, struct rex_item, cfg);

	idr_remove(&rex_item_idr, rex->id);
	rex_database_reset(rex, NULL, NULL);
	config_item_put(cfg);
}

static struct configfs_group_operations rex_group_ops = {
	.make_item = rex_make_item,
	.drop_item = rex_drop_item,
};

static const struct config_item_type rex_group_type = {
	.ct_owner	= THIS_MODULE,
	.ct_group_ops	= &rex_group_ops,
};

static struct configfs_subsystem rex_configfs = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "rex",
			.ci_type = &rex_group_type,
		},
	},
	.su_mutex = __MUTEX_INITIALIZER(rex_configfs.su_mutex),
};

static void print_banner(void)
{
	pr_info("Hyperscan %s", hs_version());
	pr_info("CPU: ");
#ifdef HAVE_SSE2
	pr_cont(" sse2");
#endif
#ifdef HAVE_SSE41
	pr_cont(" sse41");
#endif
#ifdef HAVE_SSE42
	pr_cont(" sse42");
#endif
#ifdef HAVE_AVX
	pr_cont(" avx");
#endif
#ifdef HAVE_AVX2
	pr_cont(" avx2");
#endif
#ifdef HAVE_AVX512
	pr_cont(" avx512");
#endif
#ifdef HAVE_AVX512VBMI
	pr_cont(" avx512_vbmi");
#endif
#ifdef HAVE_POPCOUNT_INSTR
	pr_cont(" popcount");
#endif
	pr_cont("\n");
}

static int __init xdp_rex_init(void)
{
	int ret;
	struct config_group *root = &rex_configfs.su_group;

	print_banner();

	config_group_init(root);
	if ((ret = configfs_register_subsystem(&rex_configfs)))
		return ret;

	register_kfunc_btf_id_set(&prog_test_kfunc_list, &xdp_rex_kfunc_btf_set);

	return 0;
}


static void __exit xdp_rex_exit(void)
{
	unregister_kfunc_btf_id_set(&prog_test_kfunc_list, &xdp_rex_kfunc_btf_set);

	configfs_unregister_subsystem(&rex_configfs);
	pr_info("xdp_rex_exit\n");
}

module_init(xdp_rex_init);
module_exit(xdp_rex_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hyperscan regex engine");
