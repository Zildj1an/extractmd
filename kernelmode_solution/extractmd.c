#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/mount.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <asm/segment.h>
#include <asm/uaccess.h>

#include "extractmd.h"
#include "linux-4.0.9/fs/ext4/ext4.h"

static int __init init_extractmd(void);
static void __exit cleanup_extractmd(void);
static int extractmd_ioctl(struct inode *, struct file *, struct extractmd_path *);

static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static unsigned long extractmd_pow(unsigned long , unsigned long);
static inline ext4_fsblk_t extractmd_group_first_block_no(struct super_block *, ext4_group_t);
static struct ext4_group_desc *extractmd_get_group_desc(struct super_block *, ext4_group_t);

ext4_fsblk_t extractmd_block_bitmap(struct super_block *, struct ext4_group_desc *);
ext4_fsblk_t extractmd_inode_table(struct super_block *, struct ext4_group_desc *);
ext4_fsblk_t extractmd_inode_bitmap(struct super_block *, struct ext4_group_desc *);

long extractmd_write_file(char *, char *, unsigned long);
long extractmd_write_file_per_group(char *, char *, unsigned long, int);
long extractmd_append_file(char *, char *, unsigned long);

static int extractmd_jread(struct buffer_head **, journal_t *, unsigned int);
int extractmd_journal_bmap(journal_t *, unsigned int, unsigned int *);
static int extractmd_do_readahead(journal_t *, unsigned int);
static void extractmd_journal_brelse_array(struct buffer_head *b[], int);

#define DEVICE_NAME "extractmd" /* Dev name as it appears in /proc/devices */
#define MAJOR_NUM 199 /* Device MAJOR number */

/* Global variables are declared as static, so are global within the file.*/
static struct class *my_class;
static dev_t devt;
static struct file_operations fops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = extractmd_ioctl,
};

static int __init init_extractmd(void)
{	
	printk(KERN_INFO "Init module\n");
	register_chrdev(MAJOR_NUM, DEVICE_NAME, &fops);
	devt = MKDEV(MAJOR_NUM,0);
	my_class = class_create(THIS_MODULE, DEVICE_NAME);
    device_create(my_class, NULL, devt, NULL, DEVICE_NAME);
	
	return 0;
}

static void __exit cleanup_extractmd(void)
{
	/* Unregister the device */
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
	device_destroy(my_class, devt);
	class_destroy(my_class);
    printk(KERN_INFO "Cleaning up module.\n");
}

static int extractmd_ioctl(struct inode *inode, struct file *f, struct extractmd_path *p)
{

	struct file *fp = filp_open(p->path_mount_point, O_RDONLY, 0);
	struct file *fp_dev = filp_open(p->path_device, O_RDONLY, 0);
	
	char path_super_block[255] = {0};
	char path_group_descriptor[255] = {0};
	char path_block_bitmap[255] = {0};
	char path_inode_bitmap[255] = {0};
	char path_inode_table[255] = {0};
	char path_journal[255] = {0};

	int i = 0;
	int j = 0;

	unsigned long nr_inode_table_block; // number of inode table blocks
	unsigned long nr_journal_blocks; // number of blocks in journal device.

	struct buffer_head *bh_sb;
	struct buffer_head *bh_gd;
	struct buffer_head *bh_journal;
	struct super_block *sb = fp->f_inode->i_sb; // get super_block of vfs
	//struct super_block *sb = fp->f_path.mnt->mnt_sb;
	struct ext4_sb_info *sbi = EXT4_SB(sb); // get ext4_sb_info
	ext4_group_t nr_group = sbi->s_groups_count;
	struct block_device *bdev;
	bdev = I_BDEV(fp_dev->f_mapping->host);
	nr_inode_table_block = sbi->s_itb_per_group;
	nr_journal_blocks = be32_to_cpu(sbi->s_journal->j_superblock->s_maxlen);

	/* set path and filenames */
	sprintf(path_super_block, "%s/sb/sb", p->path);
	sprintf(path_group_descriptor, "%s/bd/bd", p->path);
	sprintf(path_block_bitmap, "%s/bd/bbitmap", p->path);
	sprintf(path_inode_bitmap, "%s/bd/ibitmap", p->path);
	sprintf(path_inode_table, "%s/bd/itable", p->path);
	sprintf(path_journal, "%s/journal/journal", p->path);

	/* freeze */

	if(!p->realtime)
		freeze_super(sb);


	/*
   	 * EXCTRACTING SECTION!
	 */

	/* super block in Group 0 */
	bh_sb = __bread(bdev, 0, EXT4_BLOCK_SIZE(sb));
	extractmd_write_file(path_super_block, bh_sb->b_data + 1024, 1024);
	//extractmd_write_file_per_group(path_super_block, bh_sb->b_data, EXT4_BLOCK_SIZE(sb), 0);

	/* groupd descriptors in Group 0 */ 
	bh_gd = __bread(bdev, 1, EXT4_BLOCK_SIZE(sb));
	for (i = 0; i < nr_group; i++)
	{
		extractmd_write_file_per_group(path_group_descriptor, bh_gd->b_data + 32*i, 32, i);
	}


	/* sparse super block v2? */
	if((sbi->s_es->s_feature_compat & 0x200))
	{
		struct buffer_head *bh_redundant_sb1;
		struct buffer_head *bh_redundant_sb2;

		bh_redundant_sb1 = __bread(bdev, extractmd_group_first_block_no(sb, sbi->s_es->s_backup_bgs[0]), EXT4_BLOCK_SIZE(sb));
		bh_redundant_sb2 = __bread(bdev, extractmd_group_first_block_no(sb, sbi->s_es->s_backup_bgs[1]), EXT4_BLOCK_SIZE(sb));
		extractmd_append_file(path_super_block, bh_redundant_sb1->b_data, 1024);
		extractmd_append_file(path_super_block, bh_redundant_sb2->b_data, 1024);
	}

	/* sparse super block?  Yes -> then sb in group 0 or a power of 3, 5, or 7 */
	else if((sbi->s_es->s_feature_ro_compat & 0x1) == 1)
	{
		unsigned long x,y,z;
		struct buffer_head *bh_redundant_sb;

		for (x = 0; extractmd_pow(3,x) < nr_group; x++)
		{
			bh_redundant_sb = __bread(bdev, extractmd_group_first_block_no(sb,extractmd_pow(3,x)), EXT4_BLOCK_SIZE(sb));
			extractmd_append_file(path_super_block, bh_redundant_sb->b_data, 1024);
		}

		for (y = 1; extractmd_pow(5,y) < nr_group; y++)
		{
			bh_redundant_sb = __bread(bdev, extractmd_group_first_block_no(sb,extractmd_pow(5,y)), EXT4_BLOCK_SIZE(sb));
			extractmd_append_file(path_super_block, bh_redundant_sb->b_data, 1024);
		}


		for (z = 1; extractmd_pow(7,z) < nr_group; z++)
		{
			bh_redundant_sb = __bread(bdev, extractmd_group_first_block_no(sb,extractmd_pow(7,z)), EXT4_BLOCK_SIZE(sb));
			extractmd_append_file(path_super_block, bh_redundant_sb->b_data, 1024);
		}
	}

	else 
	{
		int k;
		struct buffer_head *bh_redundant_sb;
		
		for (k = 1; k < nr_group; k++)
		{
			bh_redundant_sb = __bread(bdev, extractmd_group_first_block_no(sb, k), EXT4_BLOCK_SIZE(sb));
			extractmd_append_file(path_super_block, bh_redundant_sb->b_data, 1024);
		}

	}

	char *buffer_ibitmaps = kmalloc((sbi->s_inodes_per_group)/8, GFP_KERNEL);
	char *buffer_bbitmaps = kmalloc((sbi->s_clusters_per_group)/8, GFP_KERNEL);
	char *buffer_inode_table = kmalloc(EXT4_BLOCK_SIZE(sb) * nr_inode_table_block, GFP_KERNEL);
	
	/* bit maps, inode tables */
	for(i = 0; i < nr_group; i++)
	{	
		int h;
		
		struct ext4_group_desc *group = extractmd_get_group_desc(sb, i);

		if(group->bg_flags & 0x1)
		{
			
			memset(buffer_ibitmaps, 0x0,(sbi->s_inodes_per_group)/8);
			extractmd_write_file_per_group(path_inode_bitmap, buffer_ibitmaps, (sbi->s_inodes_per_group)/8, i);
		}
		else {
			struct buffer_head *bh_inode_bitmap = __bread(bdev, extractmd_inode_bitmap(sb, group), EXT4_BLOCK_SIZE(sb));
			extractmd_write_file_per_group(path_inode_bitmap, bh_inode_bitmap->b_data, (sbi->s_inodes_per_group)/8, i);
		}

		if(group->bg_flags & 0x2)
		{
			
			memset(buffer_bbitmaps, 0x0,(sbi->s_clusters_per_group)/8);
			extractmd_write_file_per_group(path_block_bitmap, buffer_bbitmaps, (sbi->s_clusters_per_group)/8, i);
		}
		else {
			struct buffer_head *bh_block_bitmap      = __bread(bdev, extractmd_block_bitmap(sb, group), EXT4_BLOCK_SIZE(sb));
			extractmd_write_file_per_group(path_block_bitmap, bh_block_bitmap->b_data, (sbi->s_clusters_per_group)/8, i);		
		}

		if(group->bg_flags & 0x4)
		{
			memset(buffer_inode_table, 0x0, EXT4_BLOCK_SIZE(sb) * nr_inode_table_block);
			extractmd_write_file_per_group(path_inode_table, buffer_inode_table, EXT4_BLOCK_SIZE(sb) * nr_inode_table_block, i);
		}
		else {
			for (h = 0; h < nr_inode_table_block; h++)
			{
				struct buffer_head *bh_inode_table = __bread(bdev, extractmd_inode_table(sb, group) + h,  EXT4_BLOCK_SIZE(sb));
				memcpy(buffer_inode_table + EXT4_BLOCK_SIZE(sb) * h, bh_inode_table->b_data, EXT4_BLOCK_SIZE(sb));
			}
			extractmd_write_file_per_group(path_inode_table , buffer_inode_table,  EXT4_BLOCK_SIZE(sb) * nr_inode_table_block, i);		
		}		
	}
	kfree(buffer_inode_table);
	kfree(buffer_ibitmaps);
	kfree(buffer_bbitmaps);

	/* journal */
	for(j = 0; j < nr_journal_blocks; j++)
	{
		if(extractmd_jread(&bh_journal, sbi->s_journal, j) == 0)
		{
			bh_journal = __bread(sbi->s_journal->j_dev, j, EXT4_BLOCK_SIZE(sb));
			extractmd_append_file(path_journal, bh_journal->b_data, EXT4_BLOCK_SIZE(sb));
		}
	}

	/* unfreeze */
	if(!p->realtime)
		thaw_super(sb);
	
	filp_close(fp, NULL);
	filp_close(fp_dev, NULL);

	return 0;
}

static unsigned long extractmd_pow(unsigned long base, unsigned long exponent)
{
	unsigned long i = 0;
	unsigned long ret = 1;


	if (exponent == 0)
	{
		return 1;
	}

	else 
	{
		for (i = 0; i < exponent; i++)
			ret = ret * base;
	}

	return ret;
}

static inline ext4_fsblk_t extractmd_group_first_block_no(struct super_block *sb, ext4_group_t group_no)
{
	return group_no * (ext4_fsblk_t)EXT4_BLOCKS_PER_GROUP(sb) + le32_to_cpu(EXT4_SB(sb)->s_es->s_first_data_block);
}

static struct ext4_group_desc *extractmd_get_group_desc(struct super_block *sb, ext4_group_t block_group)
{
	unsigned int group_desc = block_group >> EXT4_DESC_PER_BLOCK_BITS(sb);
	unsigned int offset = block_group &(EXT4_DESC_PER_BLOCK(sb) - 1);
	struct ext4_sb_info *sbi = EXT4_SB(sb);
	return (struct ext4_group_desc *)((__u8 *)sbi->s_group_desc[group_desc]->b_data + offset * EXT4_DESC_SIZE(sb));
}

ext4_fsblk_t extractmd_block_bitmap(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_block_bitmap_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (ext4_fsblk_t)le32_to_cpu(bg->bg_block_bitmap_hi) << 32 : 0);
}

ext4_fsblk_t extractmd_inode_table(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_table_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (ext4_fsblk_t)le32_to_cpu(bg->bg_inode_table_hi) << 32 : 0);
}

ext4_fsblk_t extractmd_inode_bitmap(struct super_block *sb, struct ext4_group_desc *bg)
{
	return le32_to_cpu(bg->bg_inode_bitmap_lo) | (EXT4_DESC_SIZE(sb) >= EXT4_MIN_DESC_SIZE_64BIT ? (ext4_fsblk_t)le32_to_cpu(bg->bg_inode_bitmap_hi) << 32 : 0);
}

/* Called when a process tries to open the device file */
static int device_open(struct inode *inode, struct file *file)
{
	return 0;
}

/* Called when a process closes the device file */
static int device_release(struct inode *inode, struct file *file)
{
	return 0;
}


long extractmd_write_file(char *path, char *data, unsigned long size)
{
	long ret;
	char filename[255] = {0};
	struct file *fp;

	mm_segment_t fs;
	fs = get_fs();
	set_fs(KERNEL_DS);

	sprintf(filename, "%s.bin", path);
	fp = filp_open(filename, O_WRONLY | O_CREAT, 0777);
	ret = vfs_write(fp, data, size, &fp->f_pos);
	
	set_fs(fs);
	filp_close(fp, NULL);
    return ret;
}

long extractmd_write_file_per_group(char *path, char *data, unsigned long size, int num)
{
	long ret;
	char filename[255] = {0};
	struct file *fp;

	mm_segment_t fs;
	fs = get_fs();
	set_fs(KERNEL_DS);

	sprintf(filename, "%s%d.bin", path, num);
	fp = filp_open(filename, O_WRONLY | O_CREAT, 0777);
	ret = vfs_write(fp, data, size, &fp->f_pos);
	
	set_fs(fs);
	filp_close(fp, NULL);
    return ret;
}

long extractmd_append_file(char *path, char* data, unsigned long size)
{
	long ret;
	char filename[255] = {0};
	struct file *fp;

	mm_segment_t fs;
	fs = get_fs();
	set_fs(KERNEL_DS);

	sprintf(filename, "%s.bin", path);
	fp = filp_open(filename, O_WRONLY | O_APPEND | O_CREAT, 0777);
	ret = vfs_write(fp, data, size, &fp->f_pos);
	
	set_fs(fs);
	filp_close(fp, NULL);
    return ret;
}

static int extractmd_jread(struct buffer_head **bhp, journal_t *journal, unsigned int offset)
{
	int err;
	unsigned int blocknr;
	struct buffer_head *bh;

	*bhp = NULL;

	if (offset >= journal->j_maxlen) {
		printk(KERN_ERR "JBD: corrupted journal superblock\n");
		return -EIO;
	}

	err = extractmd_journal_bmap(journal, offset, &blocknr);

	if (err) {
		printk (KERN_ERR "JBD: bad block at offset %u\n",
			offset);
		return err;
	}

	bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);

	if (!bh)
		return -ENOMEM;

	if (!buffer_uptodate(bh)) {
		/* If this is a brand new buffer, start readahead.
                   Otherwise, we assume we are already reading it.  */
		if (!buffer_req(bh))
			extractmd_do_readahead(journal, offset);
		wait_on_buffer(bh);
	}

	if (!buffer_uptodate(bh)) {
		printk (KERN_ERR "JBD: Failed to read block at offset %u\n",
			offset);
		brelse(bh);
		return -EIO;
	}

	*bhp = bh;
	return 0;
}

int extractmd_journal_bmap(journal_t *journal, unsigned int blocknr, unsigned int *retp)
{
	int err = 0;
	unsigned int ret;

	if (journal->j_inode) {
		ret = bmap(journal->j_inode, blocknr);
		if (ret)
			*retp = ret;
		else {
			char b[BDEVNAME_SIZE];

			printk(KERN_ALERT "%s: journal block not found "
					"at offset %u on %s\n",
				__func__,
				blocknr,
				bdevname(journal->j_dev, b));
			err = -EIO;
			//__journal_abort_soft(journal, err);
		}
	} else {
		*retp = blocknr; /* +journal->j_blk_offset */
	}
	return err;
}

#define MAXBUF 8
static int extractmd_do_readahead(journal_t *journal, unsigned int start)
{
	int err;
	unsigned int max, nbufs, next;
	unsigned int blocknr;
	struct buffer_head *bh;

	struct buffer_head * bufs[MAXBUF];

	/* Do up to 128K of readahead */
	max = start + (128 * 1024 / journal->j_blocksize);
	if (max > journal->j_maxlen)
		max = journal->j_maxlen;

	/* Do the readahead itself.  We'll submit MAXBUF buffer_heads at
	 * a time to the block device IO layer. */

	nbufs = 0;

	for (next = start; next < max; next++) {
		err = extractmd_journal_bmap(journal, next, &blocknr);

		if (err) {
			printk (KERN_ERR "JBD: bad block at offset %u\n",
				next);
			goto failed;
		}

		bh = __getblk(journal->j_dev, blocknr, journal->j_blocksize);
		if (!bh) {
			err = -ENOMEM;
			goto failed;
		}

		if (!buffer_uptodate(bh) && !buffer_locked(bh)) {
			bufs[nbufs++] = bh;
			if (nbufs == MAXBUF) {
				ll_rw_block(READ, nbufs, bufs);
				extractmd_journal_brelse_array(bufs, nbufs);
				nbufs = 0;
			}
		} else
			brelse(bh);
	}

	if (nbufs)
		ll_rw_block(READ, nbufs, bufs);
	err = 0;

failed:
	if (nbufs)
		extractmd_journal_brelse_array(bufs, nbufs);
	return err;
}

static void extractmd_journal_brelse_array(struct buffer_head *b[], int n)
{
	while (--n >= 0)
		brelse (b[n]);
}

module_init(init_extractmd);
module_exit(cleanup_extractmd);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mincheol Sung <mincheol@vt.edu>");
MODULE_DESCRIPTION("Extract meta data of EXT4 from the device and write it on files.");
