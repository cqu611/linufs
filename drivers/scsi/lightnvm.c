/*
 * ufs-lightnvm.c - LightNVM UFS device
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139,
 * USA.
 *
 */
#include <linux/module.h>
#include <linux/moduleparam.h>

#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_request.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>

#include <linux/bitops.h>
#include <linux/lightnvm.h> 
#include <linux/vmalloc.h>
#include <linux/sched/sysctl.h>
#include <uapi/linux/lightnvm.h>

#include "/root/linufs/drivers/scsi/sd.h"

#define UFS_NVM_LP_MLC_PAIRS 886
#define SCSI_MAX_CDBLEN 16
#define UFS_DEVICE_CQU_QEMU	"qemu-test"	/* Not Used */
#define UFS_VENDOR_CQU		   	0xeeee

static LIST_HEAD(nullnvm_list);
static struct mutex lock;
static int nullnvm_major;
static int nullnvm_indexes;
static struct kmem_cache *ppa_cache;


enum ufs_nvm_opcode {
	UFS_NVM_ADMIN_IDENTITY		= 0xe1,
	UFS_NVM_ADMIN_GET_L2P_TBL	= 0xe2,
	UFS_NVM_ADMIN_SET_BB_TBL	= 0xe3,
	UFS_NVM_ADMIN_GET_BB_TBL	= 0xe4,
	UFS_NVM_OP_HBREAD		= 0xc1,
	UFS_NVM_OP_HBWRITE		= 0xc2,
	UFS_NVM_OP_PWRITE		= 0xc3,
	UFS_NVM_OP_PREAD		= 0xc4,
	UFS_NVM_OP_ERASE		= 0xc5,
};

struct ufs_nvm_l2p_mlc {
	__le16			num_pairs;
	__u8			pairs[UFS_NVM_LP_MLC_PAIRS];
};

struct ufs_nvm_l2p_tbl {
	__u8			id[8];
	struct ufs_nvm_l2p_mlc	mlc;
};

struct ufs_nvm_id_group {
	__u8			mtype;
	__u8			fmtype;
	__le16			res16;
	__u8			num_ch;
	__u8			num_lun;
	__u8			num_pln;
	__u8			rsvd1;
	__le16			num_blk;
	__le16			num_pg;
	__le16			fpg_sz;
	__le16			csecs;
	__le16			sos;
	__le16			rsvd2;
	__le32			trdt;
	__le32			trdm;
	__le32			tprt;
	__le32			tprm;
	__le32			tbet;
	__le32			tbem;
	__le32			mpos;
	__le32			mccap;
	__le16			cpar;
	__u8			reserved[10];
	struct ufs_nvm_l2p_tbl lptbl;
} __packed;

struct ufs_nvm_addr_format {
	__u8			ch_offset;
	__u8			ch_len;
	__u8			lun_offset;
	__u8			lun_len;
	__u8			pln_offset;
	__u8			pln_len;
	__u8			blk_offset;
	__u8			blk_len;
	__u8			pg_offset;
	__u8			pg_len;
	__u8			sect_offset;
	__u8			sect_len;
	__u8			res[4];
} __packed;

struct ufs_nvm_id {
	__u8			ver_id;
	__u8			vmnt;
	__u8			cgrps;
	__u8			res;
	__le32			cap;
	__le32			dom;
	struct ufs_nvm_addr_format ppaf;
	__u8			resv[228];
	struct ufs_nvm_id_group groups[4];
} __packed;

struct ufs_nvm_bb_tbl {
	__u8	tblid[4];
	__le16	verid;
	__le16	revid;
	__le32	rvsd1;
	__le32	tblks;
	__le32	tfact;
	__le32	tgrown;
	__le32	tdresv;
	__le32	thresv;
	__le32	rsvd2[8];
	__u8	blk[0];

};

static inline bool ufs_nvm_is_write(struct scsi_cmnd *cmd)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_is_write(), started\n");
	pr_info("LIGHTNVM_UFS: ufs_nvm_is_write(), scsi_cmnd = %#x\n", cmd);
	pr_info("LIGHTNVM_UFS: ufs_nvm_is_write(), scsi_cmnd->cmnd = %#x\n", cmd->cmnd);
	if (cmd->cmnd[0] == 0xc4)
		return 1;
	return 0;
}

static inline struct request *ufs_nvm_alloc_request(struct request_queue *q,
			struct scsi_cmnd *cmd)
{
	unsigned op = ufs_nvm_is_write(cmd) ? REQ_OP_DRV_OUT : REQ_OP_DRV_IN;
	struct request *req;

	pr_info("LIGHTNVM_UFS: ufs_nvm_alloc_request(), started\n");
	pr_info("LIGHTNVM_UFS: ufs_nvm_alloc_request(), request_queue = %#x\n", q);
	pr_info("LIGHTNVM_UFS: ufs_nvm_alloc_request(), op = %#x\n", op);
	return (struct request*)0;
	req = blk_mq_alloc_request(q, op, 0);
	if (IS_ERR(req))
		return req;
	req->cmd_flags |= REQ_FAILFAST_DRIVER;
	scsi_req(req)->cmd = cmd->cmnd;

	return req;
}

int nullnvm_identity(struct scsi_cmnd *cmd, struct ufs_nvm_id *id, unsigned bufflen) 
{
	sector_t size = 250 * 1024 * 1024 * 1024ULL;
	sector_t blksize;
	struct ufs_nvm_id_group *grp;
				
	id->ver_id = 0x1;
	id->vmnt = 0;
	id->cgrps = 1;
	id->cap = 0x2;
	id->dom = 0x1;

	id->ppaf.blk_offset = 0;
	id->ppaf.blk_len = 16;
	id->ppaf.pg_offset = 16;
	id->ppaf.pg_len = 16;
	id->ppaf.sect_offset = 32;
	id->ppaf.sect_len = 8;
	id->ppaf.pln_offset = 40;
	id->ppaf.pln_len = 8;
	id->ppaf.lun_offset = 48;
	id->ppaf.lun_len = 8;
	id->ppaf.ch_offset = 56;
	id->ppaf.ch_len = 8;
	
	sector_div(size, 512); /* convert size to pages */
	size >>= 8; /* concert size to pgs pr blk */
	grp = &id->groups[0];
	grp->mtype = 0;
	grp->fmtype = 0;
	grp->num_ch = 1;
	grp->num_pg = 256;
	blksize = size;
	size >>= 16;
	grp->num_lun = size + 1;
	sector_div(blksize, grp->num_lun);
	grp->num_blk = blksize;
	grp->num_pln = 1;

	grp->fpg_sz = 512;
	grp->csecs = 512;
	grp->trdt = 25000;
	grp->trdm = 25000;
	grp->tprt = 500000;
	grp->tprm = 500000;
	grp->tbet = 1500000;
	grp->tbem = 1500000;
	grp->mpos = 0x010101; /* single plane rwe */
	grp->cpar = 64;

	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ver_id = %#x\n", id->ver_id);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->vmnt = %#x\n", id->vmnt);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->cgrps = %#x\n", id->cgrps);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->cap = %#x\n", id->cap);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->dom = %#x\n", id->dom);

	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.blk_offset = %#x\n", id->ppaf.blk_offset);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.blk_len = %#x\n", id->ppaf.blk_len);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.pg_offset = %#x\n", id->ppaf.pg_offset);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.pg_len = %#x\n", id->ppaf.pg_len);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.sect_offset = %#x\n", id->ppaf.sect_offset);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.sect_len = %#x\n", id->ppaf.sect_len);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.pln_offset = %#x\n", id->ppaf.pln_offset);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.pln_len = %#x\n", id->ppaf.pln_len);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.lun_offset = %#x\n", id->ppaf.lun_offset);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.lun_len = %#x\n", id->ppaf.lun_len);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.ch_offset = %#x\n", id->ppaf.ch_offset);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), id->ppaf.ch_len = %#x\n", id->ppaf.ch_len);

	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->mtype = %#x\n", grp->mtype);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->fmtype = %#x\n", grp->fmtype);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->num_ch = %#x\n", grp->num_ch);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->num_pg = %#x\n", grp->num_pg);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->num_lun = %#x\n", grp->num_lun);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->num_blk = %#x\n", grp->num_blk);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->num_pln = %#x\n", grp->num_pln);
	
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->fpg_sz = %#x\n", grp->fpg_sz);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->fpg_sz = %#x\n", grp->fpg_sz);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->csecs = %#x\n", grp->csecs);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->trdt = %#x\n", grp->trdt);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->trdm = %#x\n", grp->trdm);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->tprt = %#x\n", grp->tprt);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->tprm = %#x\n", grp->tprm);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->tbet = %#x\n", grp->tbet);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->tbem = %#x\n", grp->tbem);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->mpos = %#x\n", grp->mpos);
	pr_info("LIGHTNVM_UFS: nullnvm_identity(), grp->cpar = %#x\n", grp->cpar);
	return 0;
}

int nullnvm_get_l2p_tbl(struct scsi_cmnd *cmd, struct ufs_nvm_l2p_tbl *l2p, unsigned bufflen)
{
	return 0;
}

int nullnvm_get_bb_tbl(struct scsi_cmnd *cmd, struct ufs_nvm_bb_tbl *bb, unsigned bufflen)
{
	return 0;
}

int nullnvm_set_bb_tbl(struct scsi_cmnd *cmd)
{
	return 0;
}

int ufs_submit_sync_cmd(struct request_queue *q, struct scsi_cmnd *cmd,
				void *buffer, unsigned bufflen)
{
	struct request *req;
	int ret;

	switch(cmd->cmnd[0]) 
	{
		case UFS_NVM_ADMIN_IDENTITY:
			pr_info("LIGHTNVM_UFS: ufs_submit_sync_cmd(), cmd = UFS_NVM_ADMIN_IDENTITY\n");
			return nullnvm_identity(cmd, (struct ufs_nvm_id*) buffer, bufflen);
		case UFS_NVM_ADMIN_GET_L2P_TBL:
			pr_info("LIGHTNVM_UFS: ufs_submit_sync_cmd(), cmd = UFS_NVM_ADMIN_GET_L2P_TBL\n");
			return nullnvm_get_l2p_tbl(cmd, (struct ufs_nvm_l2p_tbl*) buffer, bufflen);
		case UFS_NVM_ADMIN_SET_BB_TBL:
			pr_info("LIGHTNVM_UFS: ufs_submit_sync_cmd(), cmd = UFS_NVM_ADMIN_SET_BB_TBL\n");
			return nullnvm_set_bb_tbl(cmd);
		case UFS_NVM_ADMIN_GET_BB_TBL:
			pr_info("LIGHTNVM_UFS: ufs_submit_sync_cmd(), cmd = UFS_NVM_ADMIN_GET_BB_TBL\n");
			return nullnvm_get_bb_tbl(cmd, (struct ufs_nvm_bb_tbl*) buffer, bufflen);
		default:
			pr_info("LIGHTNVM_UFS: ufs_submit_sync_cmd(), Command can not be identified\n");
			return 0;
	}

	pr_info("LIGHTNVM_UFS: ufs_submit_sync_cmd(), started\n");
	req = ufs_nvm_alloc_request(q, cmd);
	if (IS_ERR(req))
		return PTR_ERR(req);

	if (buffer && bufflen) {
		ret = blk_rq_map_kern(q, req, buffer, bufflen, GFP_KERNEL);
		if (ret)
			goto out;
	}

	blk_execute_rq(req->q, NULL, req, 0);
	if (scsi_req(req)->result == DID_OK)
		return scsi_req(req)->result;
	else
		return -EINTR;

out:
	blk_mq_free_request(req);
	return ret;
}

static inline void _ufs_nvm_check_size(void)
{
	pr_info("LIGHTNVM_UFS: _ufs_nvm_check_size(), started\n");
	BUILD_BUG_ON(sizeof(struct ufs_nvm_id_group) != 960);
	BUILD_BUG_ON(sizeof(struct ufs_nvm_addr_format) != 16);
	BUILD_BUG_ON(sizeof(struct ufs_nvm_id) != 4096);
	BUILD_BUG_ON(sizeof(struct ufs_nvm_bb_tbl) != 64);
}

static int init_grps(struct nvm_id *nvmid, struct ufs_nvm_id *ufs_nvmid)
{
	struct ufs_nvm_id_group *src;
	struct nvm_id_group *dst;

	pr_info("LIGHTNVM_UFS: init_grps(), started\n");
	if (ufs_nvmid->cgrps != 1)
		return -EINVAL;

	src = &ufs_nvmid->groups[0];
	dst = &nvmid->grp;

	dst->mtype = src->mtype;
	dst->fmtype = src->fmtype;
	dst->num_ch = src->num_ch;
	dst->num_lun = src->num_lun;
	dst->num_pln = src->num_pln;

	dst->num_pg = le16_to_cpu(src->num_pg);
	dst->num_blk = le16_to_cpu(src->num_blk);
	dst->fpg_sz = le16_to_cpu(src->fpg_sz);
	dst->csecs = le16_to_cpu(src->csecs);
	dst->sos = le16_to_cpu(src->sos);
	dst->cpar = le16_to_cpu(src->cpar);
	
	dst->trdt = le32_to_cpu(src->trdt);
	dst->trdm = le32_to_cpu(src->trdm);
	dst->tprt = le32_to_cpu(src->tprt);
	dst->tprm = le32_to_cpu(src->tprm);
	dst->tbet = le32_to_cpu(src->tbet);
	dst->tbem = le32_to_cpu(src->tbem);
	dst->mpos = le32_to_cpu(src->mpos);
	dst->mccap = le32_to_cpu(src->mccap);

	if (dst->fmtype == NVM_ID_FMTYPE_MLC) {
		memcpy(dst->lptbl.id, src->lptbl.id, 8);
		dst->lptbl.mlc.num_pairs = le16_to_cpu(src->lptbl.mlc.num_pairs);
		if (dst->lptbl.mlc.num_pairs > UFS_NVM_LP_MLC_PAIRS) {
			pr_info("nvm: number of MLC pairs not supported\n");
			return -EINVAL;
		}

		memcpy(dst->lptbl.mlc.pairs, src->lptbl.mlc.pairs, 
				dst->lptbl.mlc.num_pairs);
	}
	return 0;
}

static int ufs_nvm_identity(struct nvm_dev *nvmdev, struct nvm_id *nvmid)
{
	struct scsi_device *sdev = nvmdev->q->queuedata;
	struct ufs_nvm_id *ufs_nvmid;
	struct scsi_cmnd *cmd;
	unsigned char *cdb;
	int ret, i;

	pr_info("LIGHTNVM_UFS: ufs_nvm_identity(), started\n");
	cmd = kzalloc(sizeof(struct scsi_cmnd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;
	cdb = kzalloc(SCSI_MAX_CDBLEN, GFP_KERNEL);
	if (!cdb)
		return -ENOMEM;
	ufs_nvmid = kzalloc(sizeof(struct ufs_nvm_id), GFP_KERNEL);
	if (!ufs_nvmid)
		return -ENOMEM;

	cdb[0] = UFS_NVM_ADMIN_IDENTITY;
	cdb[1] = sdev->channel;
	for (i=2; i < SCSI_MAX_CDBLEN; i++) {
		cdb[i] = 0x00;
	}
	cmd->cmnd = cdb;

	ret = ufs_submit_sync_cmd(sdev->request_queue, cmd, 
					ufs_nvmid, sizeof(struct ufs_nvm_id));
	if (ret) {
		ret = -EIO;
		goto out;
	}

	nvmid->ver_id = ufs_nvmid->ver_id;
	nvmid->vmnt = ufs_nvmid->vmnt;
	nvmid->cap = le32_to_cpu(ufs_nvmid->cap);
	nvmid->dom = le32_to_cpu(ufs_nvmid->dom);
	memcpy(&nvmid->ppaf, &ufs_nvmid->ppaf, sizeof(struct nvm_addr_format));
	ret = init_grps(nvmid, ufs_nvmid);

out:
	kfree(ufs_nvmid);
	return ret;
}

static int ufs_nvm_get_l2p_tbl(struct nvm_dev *nvmdev, u64 slba, u32 nlb,
				nvm_l2p_update_fn *update_l2p, void *priv)
{
	struct scsi_device *sdev = nvmdev->q->queuedata;
	struct scsi_cmnd *cmd;
	u32 len = queue_max_hw_sectors(sdev->request_queue) << 9;
	u32 nlb_pr_rq = len / sizeof(u64);
	u64 cmd_slba = slba;
	void *entries;
	unsigned char *cdb;
	int ret = 0;

	pr_info("LIGHTNVM_UFS: ufs_nvm_get_l2p_tbl(), started\n");
	cmd = kzalloc(sizeof(struct scsi_cmnd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cdb = kzalloc(SCSI_MAX_CDBLEN, GFP_KERNEL);
	if (!cdb)
		return -ENOMEM;
	/* construct cdb field */
	cdb[0] = UFS_NVM_ADMIN_GET_L2P_TBL;
	cdb[1] = (unsigned char)sdev->channel;
	cdb[2] = 0x00;
	cdb[3] = 0x00;
	entries = kmalloc(len, GFP_KERNEL);
	if (!entries)
		return -ENOMEM;
	cmd->cmnd = cdb;

	while (nlb) {
		u32 cmd_nlb = min(nlb_pr_rq, nlb);
		u64 elba = slba + cmd_nlb;

		cdb[4] = (unsigned char)(cmd_nlb >> 24);
		cdb[5] = (unsigned char)((cmd_nlb >> 16) & 0x000000ff);
		cdb[6] = (unsigned char)((cmd_nlb >> 8) & 0x000000ff);
		cdb[7] = (unsigned char)(cmd_nlb & 0x000000ff);
		cdb[8] = (unsigned char)(cmd_slba >> 56);
		cdb[9] = (unsigned char)((cmd_slba >> 48) & 0x00000000000000ff);
		cdb[10] = (unsigned char)((cmd_slba >> 40) & 0x00000000000000ff);
		cdb[11] = (unsigned char)((cmd_slba >> 32) & 0x00000000000000ff);
		cdb[12] = (unsigned char)((cmd_slba >> 24) & 0x00000000000000ff);
		cdb[13] = (unsigned char)((cmd_slba >> 16) & 0x00000000000000ff);
		cdb[14] = (unsigned char)((cmd_slba >> 8) & 0x00000000000000ff);
		cdb[15] = (unsigned char)(cmd_slba & 0x00000000000000ff);

		ret = ufs_submit_sync_cmd(sdev->request_queue, cmd, entries, len);
		if (ret) {
			dev_err(&(sdev->sdev_dev), "L2P table transfer failed (%d)\n", ret);
			ret = -EIO;
			goto out;
		}

		if (unlikely(elba > nvmdev->total_secs)) {
			pr_info("LIGHTNVM_UFS: L2P data from device is out of bounds!\n");
			ret = -EINVAL;
			goto out;
		}

		/* Transform physical address to target address space */
		nvm_part_to_tgt(nvmdev, entries, cmd_nlb);

		if (update_l2p(cmd_slba, cmd_nlb, entries, priv)) {
			ret = -EINTR;
			goto out;
		}

		cmd_slba += cmd_nlb;
		nlb -= cmd_nlb;
	}
	
out:
	kfree(entries);
	return ret;
}

static int ufs_nvm_get_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr ppa,
				u8 *blks)
{
	return 0;
	struct request_queue *q = nvmdev->q;
	struct nvm_geo *geo = &nvmdev->geo;
	struct scsi_device *sdev = q->queuedata;
	struct scsi_cmnd *cmd;
	unsigned char *cdb;
	struct ufs_nvm_bb_tbl *bb_tbl;
	int nr_blks = geo->blks_per_lun * geo->plane_mode;
	int tblsz = sizeof(struct ufs_nvm_bb_tbl) + nr_blks;
	int ret = 0;
	int i = 0;

	pr_info("LIGHTNVM_UFS: ufs_nvm_get_bb_tbl(), started\n");
	cmd = kzalloc(sizeof(struct scsi_cmnd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cdb = kzalloc(SCSI_MAX_CDBLEN, GFP_KERNEL);
	if (!cdb)
		return -ENOMEM;
	/* construct cdb field */
	cdb[0] = UFS_NVM_ADMIN_GET_BB_TBL;
	cdb[1] = (unsigned char)sdev->channel;
	cdb[2] = (unsigned char)ppa.ppa;
	for (i=3; i < SCSI_MAX_CDBLEN; i++) {
		cdb[i] = 0x00;
	}
	cmd->cmnd = cdb;

	bb_tbl = kzalloc(tblsz, GFP_KERNEL);
	if (!bb_tbl)
		return -ENOMEM;

	ret = ufs_submit_sync_cmd(sdev->request_queue, cmd, bb_tbl, tblsz);
	if (ret) {
		dev_err(&(sdev->sdev_dev), "get bad block table failed (%d)\n", ret);
		ret = -EIO;
		goto out;
	}
	if (bb_tbl->tblid[0] != 'B' || bb_tbl->tblid[1] != 'B' ||
		bb_tbl->tblid[2] != 'L' || bb_tbl->tblid[3] != 'T') {
		dev_err(&(sdev->sdev_dev), "bbt format mismatch\n");
		ret = -EINVAL;
		goto out;
	}
	if (le16_to_cpu(bb_tbl->verid) != 1) {
		ret = -EINVAL;
		dev_err(&(sdev->sdev_dev), "bbt version not supported\n");
		goto out;
	}
	if (le32_to_cpu(bb_tbl->tblks) != nr_blks) {
		ret = -EINVAL;
		dev_err(&(sdev->sdev_dev), "bbt unsuspected blocks returned (%u!=%u)",
				le32_to_cpu(bb_tbl->tblks), nr_blks);
		goto out;
	}

	memcpy(blks, bb_tbl->blk, geo->blks_per_lun * geo->plane_mode);
out:
	kfree(bb_tbl);
	return ret;
}

static int ufs_nvm_set_bb_tbl(struct nvm_dev *nvmdev, struct ppa_addr *ppas,
				int nr_ppas, int type)
{
	return 0;
	struct request_queue *q = nvmdev->q;
	struct scsi_device *sdev = q->queuedata;
	struct scsi_cmnd *cmd;
	unsigned char *cdb;
	int ret = 0;
	int i = 0;

	pr_info("LIGHTNVM_UFS: ufs_nvm_set_bb_tbl(), started\n");
	cmd = kzalloc(sizeof(struct scsi_cmnd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	cdb = kzalloc(SCSI_MAX_CDBLEN, GFP_KERNEL);
	if (!cdb)
		return -ENOMEM;
	/* construct cdb field */
	cdb = kzalloc(SCSI_MAX_CDBLEN, GFP_KERNEL);
	cdb[0] = UFS_NVM_ADMIN_SET_BB_TBL;
	cdb[1] = (unsigned char)type;
	cdb[2] = (unsigned char)((nr_ppas & 0x0000ff00) >> 8);
	cdb[3] = (unsigned char)(nr_ppas & 0x000000ff);
	for (i = 4; i < SCSI_MAX_CDBLEN; i++) {
		cdb[i] = 0x00;
	}
	cmd->cmnd = cdb;

	ret = ufs_submit_sync_cmd(sdev->request_queue, cmd, NULL, 0);
	if (ret)
		dev_err(&(sdev->sdev_dev), "set bad block table failed (%d)\n", ret);
	return ret;
}

static inline int ufs_nvm_rq2cmd(struct nvm_rq *rqd, struct scsi_device *sdev,
				struct scsi_cmnd *cmd)
{
	unsigned char *cdb;
	int i;

	pr_info("LIGHTNVM_UFS: ufs_nvm_rq2cmd(), started\n");
	cdb = kzalloc(SCSI_MAX_CDBLEN, GFP_KERNEL);
	if (!cdb)
		return -ENOMEM;
	/* construct cdb field */
	if (rqd->opcode == NVM_OP_HBREAD) {
		cdb[0] = UFS_NVM_OP_HBREAD;
		cdb[4] = (unsigned char)(rqd->flags >> 8);
		cdb[5] = (unsigned char)(rqd->flags & 0x00ff);
	} else if (rqd->opcode == NVM_OP_PREAD) {
		cdb[0] = UFS_NVM_OP_PREAD;
		cdb[4] = (unsigned char)(rqd->flags >> 8);
		cdb[5] = (unsigned char)(rqd->flags & 0x00ff);
	} else if (rqd->opcode == NVM_OP_HBWRITE) {
		cdb[0] = UFS_NVM_OP_HBWRITE;
		cdb[4] = (unsigned char)(rqd->flags >> 8);
		cdb[5] = (unsigned char)(rqd->flags & 0x00ff);
	} else if (rqd->opcode == NVM_OP_PWRITE) {
		cdb[0] = UFS_NVM_OP_PWRITE;
		cdb[4] = (unsigned char)(rqd->flags >> 8);
		cdb[5] = (unsigned char)(rqd->flags & 0x00ff);
	} else if (rqd->opcode == NVM_OP_ERASE) {
		cdb[0] = UFS_NVM_OP_ERASE;
		cdb[4] = 0x00;
		cdb[5] = 0x00;
	} else {
		goto out;
	}
	cdb[1] = 0x00;
	cdb[2] = (unsigned char)(rqd->nr_ppas >> 8);
	cdb[3] = (unsigned char)(rqd->nr_ppas & 0x00ff);
	cdb[6] = 0x00;
	cdb[7] = 0x00;
	for (i=8; i < SCSI_MAX_CDBLEN; i++) {
		cdb[i] = 0x00;
	}
	cmd->cmnd = cdb;
	return 0;

	out:
	kfree(cdb);	
	return -1;
}

static void ufs_nvm_end_io(struct request *rq, blk_status_t error) 
{
	struct nvm_rq *rqd = rq->end_io_data;

	pr_info("LIGHTNVM_UFS: ufs_nvm_end_io(), started\n");
	rqd->ppa_status = le64_to_cpu(scsi_req(rq)->result);
	rqd->error = scsi_req(rq)->result;
	nvm_end_io(rqd);

	kfree(scsi_req(rq)->cmd);
	blk_mq_free_request(rq);
}

static int ufs_nvm_submit_io(struct nvm_dev *nvmdev, struct nvm_rq *rqd)
{
	struct request_queue *q = nvmdev->q;
	struct scsi_device *sdev = q->queuedata;
	struct request *rq;
	struct bio *bio = rqd->bio;
	struct scsi_cmnd *cmd;
	int i=0;

	pr_info("LIGHTNVM_UFS: ufs_nvm_submit_io(), started\n");
	cmd = kzalloc(sizeof(struct scsi_cmnd), GFP_KERNEL);
	if (!cmd)
		return -ENOMEM;

	ufs_nvm_rq2cmd(rqd, sdev, cmd);
	for (i=0; i < 16; i++)
		pr_info("LIGHTNVM_UFS: ufs_nvm_submit_io(), cdb[%d] = %#x\n", i, cmd->cmnd[i]);
	return 0;

	rq = ufs_nvm_alloc_request(q, cmd);
	if (IS_ERR(rq)) {
		kfree(cmd);
		return -ENOMEM;
	}
	rq->cmd_flags &= ~REQ_FAILFAST_DRIVER;

	if (bio) {
		blk_init_request_from_bio(rq, bio);
	} else {
		rq->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NORM);
		rq->__data_len = 0;
	}

	rq->end_io_data = rqd;
	blk_execute_rq_nowait(q, NULL, rq, 0, ufs_nvm_end_io);
	
	return 0;
}

static void *ufs_nvm_create_dma_pool(struct nvm_dev *ndev, char *name)
{
	struct scsi_disk *sdev = ndev->private_data;
	mempool_t *virtmem_pool;

	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), started\n");
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), nvm_dev->ops = %#x\n", ndev->ops);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), nvm_dev->dma_pool = %#x\n", ndev->dma_pool);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), nvm_dev->q = %#x\n", ndev->q);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), nvm_dev->private_data = %#x\n", ndev->private_data);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), scsi_disk->driver = %#x\n", sdev->driver);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), scsi_disk->device = %#x\n", sdev->device);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), scsi_disk->dev = %#x\n", sdev->dev);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), scsi_disk->disk = %#x\n", sdev->disk);
	pr_info("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), scsi_disk->nvmdev = %#x\n", sdev->nvmdev);
	//return dma_pool_create(name, &(sdev->dev), PAGE_SIZE, PAGE_SIZE, 0);
	//return 1;
	
	virtmem_pool = mempool_create_slab_pool(64, ppa_cache);
	if (!virtmem_pool) {
		pr_err("LIGHTNVM_UFS: ufs_nvm_create_dma_pool(), failed\n");
		return NULL;
	}

	return virtmem_pool;
}

static void ufs_nvm_destroy_dma_pool(void *pool) 
{
	//struct dma_pool *dma_pool = pool;

	pr_info("LIGHTNVM_UFS: ufs_nvm_destroy_dma_pool(), started\n");
	//dma_pool_destroy(dma_pool);
	mempool_destroy(pool);
}

static void *ufs_nvm_dev_dma_alloc(struct nvm_dev *nvmdev, void *pool,
				gfp_t mem_flags, dma_addr_t *dma_handler)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_dev_dma_alloc(), started\n");
	//return dma_pool_alloc(pool, mem_flags, dma_handler);
	return mempool_alloc(pool, mem_flags);
}

static void ufs_nvm_dev_dma_free(void * pool, void *addr,
				dma_addr_t dma_handler)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_dev_dma_free(), started\n");
	// dma_pool_free(pool, addr, dma_handler);
	mempool_free(addr, pool);
}

static struct nvm_dev_ops ufs_nvm_dev_ops = {
	.identity		= ufs_nvm_identity,
		
	.get_l2p_tbl	= ufs_nvm_get_l2p_tbl,

	.get_bb_tbl		= ufs_nvm_get_bb_tbl,
	.set_bb_tbl		= ufs_nvm_set_bb_tbl,

	.submit_io		= ufs_nvm_submit_io,

	.create_dma_pool	= ufs_nvm_create_dma_pool,
	.destroy_dma_pool	= ufs_nvm_destroy_dma_pool,
	.dev_dma_alloc		= ufs_nvm_dev_dma_alloc,
	.dev_dma_free		= ufs_nvm_dev_dma_free,

	.max_phys_sect		= 64,
};

static void ufs_nvm_end_user_vio(struct request *rq, int error)
{
	struct completion *waiting = rq->end_io_data;
	pr_info("LIGHTNVM_UFS: ufs_nvm_end_user_vio(), started\n");
	complete(waiting);
}

static int ufs_nvm_submit_vio(struct scsi_disk *sd, struct nvm_user_vio __user *uvio)
{
	struct nvm_user_vio vio;
	/*
	struct scsi_cmnd cmd;
	unsigned int length;
	*/
	int ret = 0;

	pr_info("LIGHTNVM_UFS: ufs_nvm_submit_vio(), started\n");
	if (copy_from_user(&vio, uvio, sizeof(vio)))
		return -EFAULT;
	if (vio.flags)
		return -EINVAL;

	return ret;
}

static int ufs_nvm_submit_user_cmd(struct request_queue *q,
				struct scsi_disk *sd,
				struct scsi_cmnd *cmnd,
				void __user *ubuf, unsigned int bufflen,
				void __user *meta_buf, unsigned int meta_len,
				void __user *ppa_buf, unsigned int ppa_len,
				u32 *result, u64 *status, unsigned int timeout)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_submit_user_cmd(), started\n");
	return 0;
}

static int ufs_nvm_user_vcmd(struct scsi_disk *sd, int admin,
				struct nvm_passthru_vio __user *uvcmd)
{
	struct nvm_passthru_vio vcmd;
	/*
	struct scsi_cmnd *cmd;
	struct request_queue *q;
	unsigned int timeout = 0;
	*/
	int ret = 0;
	pr_info("LIGHTNVM_UFS: ufs_nvm_user_vcmd(), started\n");

	if (copy_from_user(&vcmd, uvcmd, sizeof(vcmd)))
		return -EFAULT;
	if ((vcmd.opcode != UFS_NVM_ADMIN_GET_BB_TBL) && (!capable(CAP_SYS_ADMIN)))
		return -EACCES;
	if (vcmd.flags)
		return -EINVAL;

	return ret;	
}

int ufs_nvm_ioctl(struct scsi_disk *sd, unsigned int cmd, void __user *arg)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_ioctl(), started\n");
	switch (cmd) {
	case NVME_NVM_IOCTL_ADMIN_VIO:
		return ufs_nvm_user_vcmd(sd, 1, arg);
	case NVME_NVM_IOCTL_IO_VIO:
		return ufs_nvm_user_vcmd(sd, 0, arg);
	case NVME_NVM_IOCTL_SUBMIT_VIO:
		return ufs_nvm_submit_vio(sd, arg);
	default:
		return -ENOTTY;
	}
}
EXPORT_SYMBOL(ufs_nvm_ioctl);


int ufs_nvm_register(struct scsi_disk *sd, char *disk_name)
{
	struct request_queue *q = sd->device->request_queue;
	struct nvm_dev *dev;

	pr_info("LIGHTNVM_UFS: ufs_nvm_register(), started\n");
	
	_ufs_nvm_check_size();
	/* without node info, so set the node as 0 */
	dev = kzalloc(sizeof(struct nvm_dev), GFP_KERNEL);
	if (!dev) {
		pr_info("LIGHTNVM_UFS: ufs_nvm_register(), nvm_dev is empty, failed\n");
		return -ENOMEM;
	}

	dev->q = q;
	memcpy(dev->name, disk_name, DISK_NAME_LEN);
	dev->ops = &ufs_nvm_dev_ops;
	dev->private_data = sd;
	sd->nvmdev = dev;

	pr_info("LIGHTNVM_UFS: ufs_nvm_register(), completed\n");
	return nvm_register(dev);
}
EXPORT_SYMBOL(ufs_nvm_register);


void ufs_nvm_unregister(struct scsi_disk *sd) 
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_unregister(), started\n");
	nvm_unregister(sd->nvmdev);
	pr_info("LIGHTNVM_UFS: ufs_nvm_unregister(), completed\n");
}
EXPORT_SYMBOL(ufs_nvm_unregister);


static ssize_t nvm_dev_attr_show(struct device *dev,
				struct device_attribute *dattr, char *page)
{
	struct scsi_disk *sd = to_scsi_disk(dev);
	struct nvm_dev *ndev = sd->nvmdev;
	struct nvm_id *id;
	struct nvm_id_group *grp;
	struct attribute *attr;
	
	pr_info("LIGHTNVM_UFS: nvm_dev_attr_show(), started\n");

	if (!ndev) {
		pr_info("LIGHTNVM_UFS: nvm_dev_attr_show(), nvm_dev is empty, failed\n");
		return 0;
	}

	id = &ndev->identity;
	grp = &id->grp;
	attr = &dattr->attr;

	if (strcmp(attr->name, "version") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->ver_id);
	} else if (strcmp(attr->name, "vendor_opcode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->vmnt);
	} else if (strcmp(attr->name, "capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->cap);
	} else if (strcmp(attr->name, "device_mode") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", id->dom);
	/* kept for compatibility */
	} else if (strcmp(attr->name, "media_manager") == 0) {
		return scnprintf(page, PAGE_SIZE, "%s\n", "gennvm");
	} else if (strcmp(attr->name, "ppa_format") == 0) {
		return scnprintf(page, PAGE_SIZE,
			"0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			id->ppaf.ch_offset, id->ppaf.ch_len,
			id->ppaf.lun_offset, id->ppaf.lun_len,
			id->ppaf.pln_offset, id->ppaf.pln_len,
			id->ppaf.blk_offset, id->ppaf.blk_len,
			id->ppaf.pg_offset, id->ppaf.pg_len,
			id->ppaf.sect_offset, id->ppaf.sect_len);
	} else if (strcmp(attr->name, "media_type") == 0) {	/* u8 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->mtype);
	} else if (strcmp(attr->name, "flash_media_type") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->fmtype);
	} else if (strcmp(attr->name, "num_channels") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_ch);
	} else if (strcmp(attr->name, "num_luns") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_lun);
	} else if (strcmp(attr->name, "num_planes") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_pln);
	} else if (strcmp(attr->name, "num_blocks") == 0) {	/* u16 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_blk);
	} else if (strcmp(attr->name, "num_pages") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->num_pg);
	} else if (strcmp(attr->name, "page_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->fpg_sz);
	} else if (strcmp(attr->name, "hw_sector_size") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->csecs);
	} else if (strcmp(attr->name, "oob_sector_size") == 0) {/* u32 */
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->sos);
	} else if (strcmp(attr->name, "read_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->trdt);
	} else if (strcmp(attr->name, "read_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->trdm);
	} else if (strcmp(attr->name, "prog_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tprt);
	} else if (strcmp(attr->name, "prog_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tprm);
	} else if (strcmp(attr->name, "erase_typ") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tbet);
	} else if (strcmp(attr->name, "erase_max") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n", grp->tbem);
	} else if (strcmp(attr->name, "multiplane_modes") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", grp->mpos);
	} else if (strcmp(attr->name, "media_capabilities") == 0) {
		return scnprintf(page, PAGE_SIZE, "0x%08x\n", grp->mccap);
	} else if (strcmp(attr->name, "max_phys_secs") == 0) {
		return scnprintf(page, PAGE_SIZE, "%u\n",
				ndev->ops->max_phys_sect);
	} else {
		return scnprintf(page,
				 PAGE_SIZE,
				 "Unhandled attr(%s) in `nvm_dev_attr_show`\n",
				 attr->name);
	}
	pr_info("LIGHTNVM_UFS: nvm_dev_attr_show(), completed\n");
}

#define NVM_DEV_ATTR_RO(_name) \
	DEVICE_ATTR(_name, S_IRUGO, nvm_dev_attr_show, NULL)

static NVM_DEV_ATTR_RO(version);
static NVM_DEV_ATTR_RO(vendor_opcode);
static NVM_DEV_ATTR_RO(capabilities);
static NVM_DEV_ATTR_RO(device_mode);
static NVM_DEV_ATTR_RO(ppa_format);
static NVM_DEV_ATTR_RO(media_manager);
static NVM_DEV_ATTR_RO(media_type);
static NVM_DEV_ATTR_RO(flash_media_type);
static NVM_DEV_ATTR_RO(num_channels);
static NVM_DEV_ATTR_RO(num_luns);
static NVM_DEV_ATTR_RO(num_planes);
static NVM_DEV_ATTR_RO(num_blocks);
static NVM_DEV_ATTR_RO(num_pages);
static NVM_DEV_ATTR_RO(page_size);
static NVM_DEV_ATTR_RO(hw_sector_size);
static NVM_DEV_ATTR_RO(oob_sector_size);
static NVM_DEV_ATTR_RO(read_typ);
static NVM_DEV_ATTR_RO(read_max);
static NVM_DEV_ATTR_RO(prog_typ);
static NVM_DEV_ATTR_RO(prog_max);
static NVM_DEV_ATTR_RO(erase_typ);
static NVM_DEV_ATTR_RO(erase_max);
static NVM_DEV_ATTR_RO(multiplane_modes);
static NVM_DEV_ATTR_RO(media_capabilities);
static NVM_DEV_ATTR_RO(max_phys_secs);

static struct attribute *nvm_dev_attrs[] = {
	&dev_attr_version.attr,
	&dev_attr_vendor_opcode.attr,
	&dev_attr_capabilities.attr,
	&dev_attr_device_mode.attr,
	&dev_attr_media_manager.attr,
	&dev_attr_ppa_format.attr,
	&dev_attr_media_type.attr,
	&dev_attr_flash_media_type.attr,
	&dev_attr_num_channels.attr,
	&dev_attr_num_luns.attr,
	&dev_attr_num_planes.attr,
	&dev_attr_num_blocks.attr,
	&dev_attr_num_pages.attr,
	&dev_attr_page_size.attr,
	&dev_attr_hw_sector_size.attr,
	&dev_attr_oob_sector_size.attr,
	&dev_attr_read_typ.attr,
	&dev_attr_read_max.attr,
	&dev_attr_prog_typ.attr,
	&dev_attr_prog_max.attr,
	&dev_attr_erase_typ.attr,
	&dev_attr_erase_max.attr,
	&dev_attr_multiplane_modes.attr,
	&dev_attr_media_capabilities.attr,
	&dev_attr_max_phys_secs.attr,
	NULL,
};

static const struct attribute_group nvm_dev_attr_group = {
	.name		= "lightnvm",
	.attrs		= nvm_dev_attrs,
};

EXPORT_SYMBOL(ufs_nvm_register_sysfs);
int ufs_nvm_register_sysfs(struct scsi_disk *sd)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_register_sysfs(), started\n");
	return sysfs_create_group(&disk_to_dev(sd->disk)->kobj, &nvm_dev_attr_group);
	pr_info("LIGHTNVM_UFS: ufs_nvm_register_sysfs(), completed\n");
}


EXPORT_SYMBOL(ufs_nvm_unregister_sysfs);
void ufs_nvm_unregister_sysfs(struct scsi_disk *sd)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_unregister_sysfs(), started\n");
	sysfs_remove_group(&disk_to_dev(sd->disk)->kobj, &nvm_dev_attr_group);
	pr_info("LIGHTNVM_UFS: ufs_nvm_unregister_sysfs(), completed\n");
}

EXPORT_SYMBOL(ufs_nvm_supported);
int ufs_nvm_supported(u16 vendor_id)
{
	pr_info("LIGHTNVM_UFS: ufs_nvm_supported(), started\n");
/*
	if (dev_desc->wmanufacturerid == UFS_VENDOR_CQU && 
		!strcmp(dev_desc->model, UFS_DEVICE_ID_CQU_QEMU))
		return 1;
*/
	if (vendor_id == UFS_VENDOR_CQU) {
		pr_info("LIGHTNVM_UFS: ufs_nvm_supported(), current device is UFS_VENDOR_CQU\n");
		return 1;
	}
	pr_info("LIGHTNVM_UFS: ufs_nvm_supported(), current device is %x\n", vendor_id);
	return 0;		
}

