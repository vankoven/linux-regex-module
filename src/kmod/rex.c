// SPDX-License-Identifier: GPL-2.0-only
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "rex.h"

#include "hs_runtime.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/configfs.h>
#include <linux/printk.h>
#include <linux/idr.h>
#include <linux/cpumask.h>
#include <linux/mutex.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <net/xdp.h>


static ulong max_db_size = 4 << 20;
module_param(max_db_size, ulong, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(max_db_size, "Maximum size of configfs upload, default=4MB");

static DEFINE_IDR(rex_idr);
static DEFINE_MUTEX(rex_config_mutex);

/** A wrapper around hs_database_t where we may store additional fields. */
struct rex_database {
	void __percpu *scratch; /* TODO: make it global */
	u8 bytes[] __aligned(8);
};

static inline hs_database_t *patterns(struct rex_database *db)
{
	if (!db)
		return NULL;
	return (hs_database_t *) db->bytes;
}

/**
 * struct rex_policy - Represent a configurable hyperscan database.
 * @id:		Handle used by BPF programs from rex_scan_bytes() kfunc (rw).
 * @epoch:	Sequential number which may be used to detect changes (ro).
 * @tag:	An arbitrary user string (rw).
 * @database:	Compiled database binary (rw).
 *
 * Contains other derived read-only parameters:
 * /info:	Brief database description.
 *
 */

struct rex_policy {
	u32 id;
	u32 epoch;
	char *tag;
	struct rex_database __rcu *database;
	struct config_item item;
};

static int rex_scan_cb(unsigned expression,
		       unsigned long long from,
		       unsigned long long to,
		       unsigned flags,
		       void *ctx)
{
	struct rex_scan_attr *attr = ctx;

	attr->last_event = (struct rex_event) {
		.expression = expression,
		.from = from,
		.to = to,
		.flags = flags,
	};

	attr->event_count += 1;

	if (attr->handler_flags & REX_SINGLE_SHOT) {
		return 1;
	} else {
		return 0;
	}
}

int bpf_scan_bytes(const void *buf, __u32 buf__sz,
		   struct rex_scan_attr *scan_attr)
{
	struct rex_policy *rex;
	struct rex_database *db;
	hs_scratch_t *scratch;
	hs_error_t err;

	WARN_ON_ONCE(!rcu_read_lock_held() && !rcu_read_lock_bh_held());

	if (unlikely(!buf || !scan_attr))
		return -EINVAL;

	rex = idr_find(&rex_idr, scan_attr->database_id);
	if (unlikely(!rex))
		return -EBADF;

	db = rcu_dereference(rex->database);
	if (unlikely(!db))
		return -ENODATA;

	scratch = this_cpu_ptr(db->scratch);

	kernel_fpu_begin();
	err = hs_scan(patterns(db), buf, buf__sz, 0, scratch,
		      rex_scan_cb, scan_attr);
	kernel_fpu_end();

	switch (err) {
	case HS_DB_MODE_ERROR:
		return -ENOEXEC;
	case HS_SCAN_TERMINATED:
		return 1;
	case HS_SUCCESS:
		return 0;
	case HS_SCRATCH_IN_USE:
	case HS_INVALID:
	case HS_UNKNOWN_ERROR:
	default:
		WARN(1, KERN_ERR "hs_scan() failed with code %d\n", (int) err);
		return -EFAULT;
	}
}
EXPORT_SYMBOL(bpf_scan_bytes);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5,18,0)
/* Based on code taken from net/core/filter.c */
static void *bpf_xdp_pointer(struct xdp_buff *xdp, u32 offset, u32 len)
{
	u32 size = xdp->data_end - xdp->data;
	void *addr = xdp->data;

	if (unlikely(offset > 0xffff || len > 0xffff))
		return ERR_PTR(-EFAULT);

	if (offset + len > size)
		return ERR_PTR(-EINVAL);

	return addr + offset;
}
#else
/* This code is taken from net/core/filter.c */
static void *bpf_xdp_pointer(struct xdp_buff *xdp, u32 offset, u32 len)
{
	u32 size = xdp->data_end - xdp->data;
	void *addr = xdp->data;
	struct skb_shared_info *sinfo = xdp_get_shared_info_from_buff(xdp);
	int i;

	if (unlikely(offset > 0xffff || len > 0xffff))
		return ERR_PTR(-EFAULT);

	if (offset + len > xdp_get_buff_len(xdp))
		return ERR_PTR(-EINVAL);

	if (offset < size) /* linear area */
		goto out;

	offset -= size;
	for (i = 0; i < sinfo->nr_frags; i++) { /* paged area */
		u32 frag_size = skb_frag_size(&sinfo->frags[i]);

		if  (offset < frag_size) {
			addr = skb_frag_address(&sinfo->frags[i]);
			size = frag_size;
			break;
		}
		offset -= frag_size;
	}
out:
	return offset + len < size ? addr + offset : NULL;
}
#endif

int bpf_xdp_scan_bytes(struct xdp_md *xdp_md, u32 offset, u32 len,
		       struct rex_scan_attr *scan_attr)
{
	struct xdp_buff *xdp = (struct xdp_buff *) xdp_md;
	void *ptr = bpf_xdp_pointer(xdp, offset, len);

	if (IS_ERR(ptr))
		return PTR_ERR(ptr);

	if (likely(ptr))
		return bpf_scan_bytes(ptr, len, scan_attr);
	else
		return -ENOTSUPP;
}
EXPORT_SYMBOL(bpf_xdp_scan_bytes);

int bpf_map_test(struct bpf_map *map)
{
	return 42;
}
EXPORT_SYMBOL(bpf_map_test);

BTF_SET_START(rex_kfunc_ids)
BTF_ID(func, bpf_scan_bytes)
BTF_ID(func, bpf_xdp_scan_bytes)
BTF_ID(func, bpf_map_test)
BTF_SET_END(rex_kfunc_ids)
static DEFINE_KFUNC_BTF_ID_SET(&rex_kfunc_ids, rex_kfunc_btf_set);

static struct rex_policy *to_policy(struct config_item *item)
{
	return item ?
		container_of(item, struct rex_policy, item) :
		NULL;
}

static ssize_t rexcfg_database_read(struct config_item *item,
				    void *outbuf, size_t size)
{
	struct rex_policy *rex = to_policy(item);
	struct rex_database *db;
	char *bytes = outbuf;
	ssize_t ret;

	rcu_read_lock();
	db = rcu_dereference(rex->database);

	if (!bytes) {
		/* In first call return size for te buffer. */
		if (!hs_database_size(patterns(db), &ret))
			ret = 0;
	} else if (size > 0) {
		/* In second call fill the buffer with data.
		   We have to check size again to avoid races. */
		if (hs_database_size(patterns(db), &ret) || ret != size) {
			ret = -ETXTBSY;
			goto out;
		}

		if (hs_serialize_database(patterns(db), &bytes, NULL)) {
			WARN(1, KERN_ERR "hs_serialize_database() failed\n");
			ret = -EIO;
		}

		/* Check that pointer wasn't overwritten. */
		BUG_ON(bytes != outbuf);
	} else {
		return 0;
	}

out:
	rcu_read_unlock();
	return ret;
}

static void rex_assign_database(struct rex_policy *rex, struct rex_database *db)
{
	db = rcu_replace_pointer(rex->database, db,
				 lockdep_is_held(&rex_config_mutex));
	rex->epoch += 1;

	if (db) {
		synchronize_rcu();
		free_percpu(db->scratch);
		kfree(db);
	}
}

static ssize_t rexcfg_database_write(struct config_item *item,
				     const void *bytes, size_t nbytes)
{
	struct rex_policy *rex = to_policy(item);
	struct rex_database *db;
	hs_scratch_t *proto = NULL;
	size_t alloc_size;
	int cpu;

	/* Drop existing database on empty write. */
	if (nbytes == 0) {
		mutex_lock(&rex_config_mutex);
		rex_assign_database(rex, NULL);
		mutex_unlock(&rex_config_mutex);
		return nbytes;
	}

	if (hs_serialized_database_size(bytes, nbytes, &alloc_size))
		return -EIO;

	db = kmalloc(sizeof(*db) + alloc_size, GFP_KERNEL);
	if (!db)
		return -ENOMEM;

	if (hs_deserialize_database_at(bytes, nbytes, patterns(db))) {
		kfree(db);
		return -EINVAL;
	}

	if (hs_alloc_scratch(patterns(db), &proto)) {
		kfree(db);
		return -ENOMEM;
	}

	BUG_ON(hs_scratch_size(proto, &alloc_size));
	db->scratch = __alloc_percpu(alloc_size, 64);
	if (!db->scratch) {
		kfree(db);
		hs_free_scratch(proto);
		return -ENOMEM;
	}

	for_each_possible_cpu(cpu) {
		hs_scratch_t *dst = per_cpu_ptr(db->scratch, cpu);
		BUG_ON(hs_init_scratch(proto, dst));
	}
	hs_free_scratch(proto);

	mutex_lock(&rex_config_mutex);
	rex_assign_database(rex, db);
	mutex_unlock(&rex_config_mutex);

	return nbytes;
}

static ssize_t rexcfg_info_show(struct config_item *item, char *str)
{
	struct rex_policy *rex = to_policy(item);
	struct rex_database *db;
	char *info;
	int ret = 0;

	rcu_read_lock();

	db = rcu_dereference(rex->database);
	if (hs_database_info(patterns(db), &info)) {
		ret = -EIO;
		goto out;
	}

	ret += sysfs_emit_at(str, ret, "%s\n", info);
	kfree(info);

out:
	rcu_read_unlock();
	return ret;
}

static ssize_t rexcfg_epoch_show(struct config_item *item, char* str)
{
	return snprintf(str, PAGE_SIZE, "%d\n", to_policy(item)->epoch);
}

static ssize_t rexcfg_id_show(struct config_item *item, char* str)
{
	return snprintf(str, PAGE_SIZE, "%d\n", to_policy(item)->id);
}

static ssize_t rexcfg_id_store(struct config_item *item, const char* str,
			       size_t length)
{
	struct rex_policy *rex = to_policy(item);
	int ret, new_id;

	if (sscanf(str, "%d", &new_id) != 1)
		return -EINVAL;

	mutex_lock(&rex_config_mutex);

	if (rex->id == new_id) {
		ret = length;
		goto out;
	}

	ret = idr_alloc(&rex_idr, rex, new_id, new_id+1, GFP_KERNEL);
	if (ret < 0)
		goto out;

	BUG_ON(idr_remove(&rex_idr, rex->id) != rex);
	rex->id = new_id;
	ret = length;

out:
	mutex_unlock(&rex_config_mutex);
	return ret;
}

/* Our subsystem hierarchy is:
 *
 * /sys/kernel/config/rex/
 *		|
 *		<policy>/
 *		|	id		(rw)
 *		|	database	(rw)
 *		|	epoch		(ro)
 *		|	info		(ro)
 *		|	tag		(rw)
 *		|
 *		<policy>/...
 */

CONFIGFS_BIN_ATTR(rexcfg_, database, NULL, 0);
CONFIGFS_ATTR_RO(rexcfg_, epoch);
CONFIGFS_ATTR_RO(rexcfg_, info);
CONFIGFS_ATTR(rexcfg_, id);

static void rexcfg_item_release(struct config_item *item)
{
	struct rex_policy *rex = to_policy(item);

	mutex_lock(&rex_config_mutex);
	BUG_ON(idr_remove(&rex_idr, rex->id) != rex);
	rex_assign_database(rex, NULL);
	mutex_unlock(&rex_config_mutex);
}

static const struct config_item_type rex_type = {
	.ct_owner		= THIS_MODULE,
	.ct_attrs		= (struct configfs_attribute*[]) {
		&rexcfg_attr_id,
		&rexcfg_attr_info,
		&rexcfg_attr_epoch,
		NULL
	},
	.ct_bin_attrs		= (struct configfs_bin_attribute*[]) {
		&rexcfg_attr_database,
		NULL,
	},
	.ct_item_ops		= &(struct configfs_item_operations) {
		.release	= rexcfg_item_release,
	}
};

static struct config_item *rex_make_item(struct config_group *group,
					 const char *name)
{
	struct rex_policy *rex;
	int id;

	rex = kzalloc(sizeof(*rex), GFP_KERNEL);
	if (!rex)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&rex_config_mutex);

	/* Patch database attribute type */
	rexcfg_attr_database.cb_max_size = max_db_size;
	config_item_init_type_name(&rex->item, name, &rex_type);

	id = idr_alloc(&rex_idr, rex, 0, U32_MAX, GFP_KERNEL);
	if (id < 0) {
		kfree(rex);
		return ERR_PTR(id);
	}
	rex->id = id;

	mutex_unlock(&rex_config_mutex);

	return &rex->item;
}

static const struct config_item_type rex_group_type = {
	.ct_owner		= THIS_MODULE,
	.ct_group_ops		= &(struct configfs_group_operations) {
		.make_item	= rex_make_item,
	},
};

static struct configfs_subsystem rex_configfs = {
	.su_mutex		= __MUTEX_INITIALIZER(rex_configfs.su_mutex),
	.su_group		= {
		.cg_item	= {
			.ci_namebuf	= "rex",
			.ci_type	= &rex_group_type,
		},
	},
};

static void print_banner(void)
{
	pr_info("Hyperscan %s", hs_version());
	pr_cont("\n");
}

static int __init rex_init(void)
{
	int ret;
	struct config_group *root = &rex_configfs.su_group;

	print_banner();

	config_group_init(root);
	if ((ret = configfs_register_subsystem(&rex_configfs)))
		return ret;

	register_kfunc_btf_id_set(&prog_test_kfunc_list, &rex_kfunc_btf_set);

	return 0;
}


static void __exit rex_exit(void)
{
	unregister_kfunc_btf_id_set(&prog_test_kfunc_list, &rex_kfunc_btf_set);
	configfs_unregister_subsystem(&rex_configfs);
	WARN_ON(!idr_is_empty(&rex_idr));
	idr_destroy(&rex_idr);
}

module_init(rex_init);
module_exit(rex_exit);

/* Module information */
MODULE_AUTHOR("Sergey Nizovtsev, sn@tempesta-tech.com");
MODULE_DESCRIPTION("Hyperscan regex engine");
MODULE_LICENSE("GPL");
