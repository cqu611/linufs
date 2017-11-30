#include "ramufs.h"

static struct ufs_geo geo = {
	.version 		= 0,
	.vnvmt 			= 0,
	.cgrps 			= 1,
	.cap 			= 0,
	.dom 			= 0,
	.ppaf = {
		.ch_off 	= 0,
		.ch_len 	= 0,
		.lun_off 	= 0,
		.lun_len 	= 0,
		.pln_off 	= 0,
		.pln_len 	= 0,
		.blk_off 	= 0,
		.blk_len 	= 0,
		.pg_off 	= 0,
		.pg_len 	= 0,
		.sect_off 	= 0,
		.sect_len 	= 0,
	},
	.ggrp = {
		.mtype 		= 0,
		.fmtype 	= 0,
		.num_ch 	= 0,
		.num_lun 	= 0,
		.num_pln 	= 0,
		.num_blk 	= 0,
		.num_pg 	= 0,
		.fpg_sz 	= 0,
		.csecs 		= 0,
		.sos 		= 0,
		.trdt 		= 0,
		.trdm 		= 0,
		.tprt 		= 0,
		.tprm 		= 0,
		.tbet 		= 0,
		.tbem 		= 0,
		.mpos 		= 0,
		.mccap 		= 0,
		.cpar 		= 0,
		.l2ptbl = {
			/* .id[8], */
			.mlc = {
				.num_pairs = 0,
				/* .pairs[886], */
			},
		},
	},
};

struct ramufs *ufs;

static ssize_t __show_ufs_geo(char *buf)
{
	return sprintf(buf, "\
	Version                         =%#04x\n\
	Vendor NVM Opcode Command Set   =%#04x\n\
	Configuration Groups            =%#04x\n\
	Capabilities                    =%#010x\n\
	Device Op Mode                  =%#010x\n", 
	geo.version, geo.vnvmt, geo.cgrps, geo.cap, geo.dom);
}

static ssize_t __show_ppa_fmt(char *buf)
{
	return sprintf(buf, "\
	Channel bit start       =%#04x\n\
	Channel bit length      =%#04x\n\
	LUN bit start           =%#04x\n\
	LUN bit length          =%#04x\n\
	Plane bit start         =%#04x\n\
	Plane bit length        =%#04x\n\
	Block bit start         =%#04x\n\
	Block bit length        =%#04x\n\
	Page bit start          =%#04x\n\
	Page bit length         =%#04x\n\
	Sector bit start        =%#04x\n\
	Sector bit length       =%#04x\n",
	geo.ppaf.ch_off, geo.ppaf.ch_len, geo.ppaf.lun_off,
	geo.ppaf.lun_len, geo.ppaf.pln_off, geo.ppaf.pln_len,
	geo.ppaf.blk_off, geo.ppaf.blk_len, geo.ppaf.pg_off, 
	geo.ppaf.pg_len, geo.ppaf.sect_off, geo.ppaf.sect_len);
}

static ssize_t __show_cfg_grp(char *buf)
{
	return sprintf(buf, "\
	Media Type                          =%#04x\n\
	Flash Media Type                    =%#04x\n\
	Number of Channels                  =%#04x\n\
	Number of LUNs                      =%#04x\n\
	Number of Planes                    =%#04x\n\
	Number of Blocks                    =%#06x\n\
	Number of Pages                     =%#06x\n\
	Page Size                           =%#06x\n\
	Controller Sector Size              =%#06x\n\
	Sector OOB Size                     =%#06x\n\
	tRD Typical                         =%#010x\n\
	tRD Max                             =%#010x\n\
	tPROG Typical                       =%#010x\n\
	tPROG Max                           =%#010x\n\
	tBERS Typical                       =%#010x\n\
	tBERS Max                           =%#010x\n\
	Multi-plane Operation Support       =%#010x\n\
	Media and Controller Capabilities   =%#010x\n\
	Channel Parallelism                 =%#06x\n",
	geo.ggrp.mtype, geo.ggrp.fmtype, geo.ggrp.num_ch,
	geo.ggrp.num_lun, geo.ggrp.num_pln, geo.ggrp.num_blk,
	geo.ggrp.num_pg, geo.ggrp.fpg_sz, geo.ggrp.csecs,
	geo.ggrp.sos, geo.ggrp.trdt, geo.ggrp.trdm, geo.ggrp.tprt, 
	geo.ggrp.tprm, geo.ggrp.tbet, geo.ggrp.tbem, geo.ggrp.mpos, 
	geo.ggrp.mccap, geo.ggrp.cpar);
}

static ssize_t __show_l2p_tbl(char *buf)
{
	char hex[2022];
	char *src, *dst;
	int i, j;

	src = geo.ggrp.l2ptbl.mlc.pairs;
	dst = hex;
	
	for (i=0; i < 27; i++) {
		for (j=0; j < 8; j++) {
			bin2hex(dst, src, 4);
			src = src + 4;
			dst = dst + 8;
			*(dst++) = 0x20;
		}
		*(dst++) = 0x0a;
	}
	for (i=0; i < 5; i++) {
		bin2hex(dst, src, 4);
		src = src + 4;
		dst = dst + 8;
		*(dst++) = 0x20;
	}
	bin2hex(dst, src, 2);
	dst = dst + 4;
	*(dst++) = 0x0a;
	*dst = 0;
	pr_err("dst - hex = %d\n", dst - &hex[0]);
	
	//bin2hex(hex, geo.ggrp.l2ptbl.mlc.pairs, 886);
	//hex[1772] = 0;

	return sprintf(buf, "\
	ID codes for READ ID command    =%#018llx\n\
	Number of Pairs                 =%06x\n\
	Pairs Values in Hexadecimal:\n%s\n", 
	(u64)geo.ggrp.l2ptbl.id, geo.ggrp.l2ptbl.mlc.num_pairs, hex);
}

	/* .l2ptbl = {
			.id[8], 
			.mlc = {
				.num_pairs = 0,
				.pairs[886],
			},
		}, */

static ssize_t ramufs_show(struct kobject *kobj, struct kobj_attribute *attr,
			char *buf)
{
	const char *name = attr->attr.name;
	
	if (strcmp(name, "ufs_geo") == 0) {
		pr_info("RAMUFS: show geometry\n");
		return __show_ufs_geo(buf);
	} else if (strcmp(name, "ppa_fmt") == 0) {
		pr_info("RAMUFS: show ppa format\n");
		return __show_ppa_fmt(buf);
	} else if (strcmp(name, "cfg_grp") == 0) {
		pr_info("RAMUFS: show configuration group\n");
		return __show_cfg_grp(buf);
	} else if (strcmp(name, "l2p_tbl") == 0) {
		pr_info("RAMUFS: show l2p table\n");
		return __show_l2p_tbl(buf);
	}
	return sprintf(buf, "Unhandled attr(%s) in `ramufs_show`\n", name);
}

static ssize_t ramufs_store(struct kobject *kobj, struct kobj_attribute *attr,
			 const char *buf, size_t count)
{
	int ret;
	const char *name = attr->attr.name;
	
	if (strcmp(name, "ufs_geo") == 0) {
		pr_info("RAMUFS: set geometry\n");
	} else if (strcmp(name, "ppa_fmt") == 0) {
		pr_info("RAMUFS: set ppa format\n");
	} else if (strcmp(name, "cfg_grp") == 0) {
		pr_info("RAMUFS: set configuration group\n");
	} else if (strcmp(name, "l2p_tbl") == 0) {
		pr_info("RAMUFS: set l2p table\n");
	}
	return -EINVAL;
/*
	ret = kstrtoint(buf, 10, &foo);
	if (ret < 0)
		return ret;

	return count;
*/
}

#define RAMUFS_ATTR(_name)			\
static struct kobj_attribute ramufs_attr_##_name =	\
	__ATTR(_name, 0664, ramufs_show, ramufs_store)

RAMUFS_ATTR(ufs_geo);
RAMUFS_ATTR(ppa_fmt);
RAMUFS_ATTR(cfg_grp);
RAMUFS_ATTR(l2p_tbl);

static struct attribute *ramufs_attrs[] = {
	&ramufs_attr_ufs_geo.attr,
	&ramufs_attr_ppa_fmt.attr,
	&ramufs_attr_cfg_grp.attr,
	&ramufs_attr_l2p_tbl.attr,
	NULL,	
};

static struct attribute_group ramufs_attr_group = {
	.attrs = ramufs_attrs,
};

static int __init ramufs_init(void)
{
	int ret = 0;

	pr_info("RAMUFS: ramufs init\n");
	ufs = kzalloc(sizeof(struct ramufs), GFP_KERNEL);
	if (!ufs) {
		pr_err("RAMUFS: kzalloc failed, out of memory\n");
		ret = -ENOMEM;
		goto out;
	}

	ufs->kobj = kobject_create_and_add("ramufs", kernel_kobj);
	if (!(ufs->kobj)) {
		pr_err("RAMUFS: kobject_create_and_add failed, out of memory\n");
		ret = -ENOMEM;
		goto free_ufs;
	}
	ret = sysfs_create_group(ufs->kobj, &ramufs_attr_group);
	if (ret) {
		pr_err("RAMUFS: sysfs_create_group failed\n");
		kobject_put(ufs->kobj);
		goto free_ufs;
	}

	pr_info("RAMUFS: ramufs loaded\n");
	return ret;

free_ufs:
	kfree(ufs);
out:
	return ret;
}

static void __exit ramufs_exit(void)
{
	pr_info("RAMUFS: ramufs exit\n");
	sysfs_remove_group(ufs->kobj, &ramufs_attr_group);
	kobject_put(ufs->kobj);
	kfree(ufs);
}

module_init(ramufs_init);
module_exit(ramufs_exit);

MODULE_AUTHOR("Gnekiah Hsiung <gnekiah@gmail.com>");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("UFS host controller ram-disk driver");
