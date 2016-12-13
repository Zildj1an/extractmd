/*
 * debugfs.c --- a program which allows you to attach an ext2fs
 * filesystem and play with it.
 *
 * Copyright (C) 1993 Theodore Ts'o.  This file may be redistributed
 * under the terms of the GNU Public License.
 *
 * Modifications by Robert Sanders <gt8134b@prism.gatech.edu>
 */

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <libgen.h>
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#else
extern int optind;
extern char *optarg;
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <fcntl.h>

#include "debugfs.h"
#include "uuid/uuid.h"
#include "e2p/e2p.h"
#include "journal.h"

#include <ext2fs/ext2_ext_attr.h>

#include "../version.h"
#include "jfs_user.h"
#include "support/plausible.h"

#include <linux/fs.h>
#include <sys/ioctl.h>

#ifndef BUFSIZ
#define BUFSIZ 8192
#endif

#ifdef CONFIG_JBD_DEBUG		/* Enabled by configure --enable-jbd-debug */
int journal_enable_debug = -1;
#endif

ss_request_table *extra_cmds;
const char *debug_prog_name;
int sci_idx;

ext2_filsys	current_fs;
quota_ctx_t	current_qctx;
ext2_ino_t	root, cwd;

static int fdDev = 0;
static int g_open_flags = 0;

static int debugfs_setup_tdb(const char *device_name, char *undo_file,
			     io_manager *io_ptr)
{
	errcode_t retval = ENOMEM;
	char *tdb_dir = NULL, *tdb_file = NULL;
	char *dev_name, *tmp_name;

	/* (re)open a specific undo file */
	if (undo_file && undo_file[0] != 0) {
		retval = set_undo_io_backing_manager(*io_ptr);
		if (retval)
			goto err;
		*io_ptr = undo_io_manager;
		retval = set_undo_io_backup_file(undo_file);
		if (retval)
			goto err;
		printf("Overwriting existing filesystem; this can be undone "
			"using the command:\n"
			"    e2undo %s %s\n\n",
			undo_file, device_name);
		return retval;
	}

	/*
	 * Configuration via a conf file would be
	 * nice
	 */
	tdb_dir = ss_safe_getenv("E2FSPROGS_UNDO_DIR");
	if (!tdb_dir)
		tdb_dir = "/var/lib/e2fsprogs";

	if (!strcmp(tdb_dir, "none") || (tdb_dir[0] == 0) ||
	    access(tdb_dir, W_OK))
		return 0;

	tmp_name = strdup(device_name);
	if (!tmp_name)
		goto errout;
	dev_name = basename(tmp_name);
	tdb_file = malloc(strlen(tdb_dir) + 9 + strlen(dev_name) + 7 + 1);
	if (!tdb_file) {
		free(tmp_name);
		goto errout;
	}
	sprintf(tdb_file, "%s/checkMD-%s.e2undo", tdb_dir, dev_name);
	free(tmp_name);

	if ((unlink(tdb_file) < 0) && (errno != ENOENT)) {
		retval = errno;
		com_err("checkMD", retval,
			"while trying to delete %s", tdb_file);
		goto errout;
	}

	retval = set_undo_io_backing_manager(*io_ptr);
	if (retval)
		goto errout;
	*io_ptr = undo_io_manager;
	retval = set_undo_io_backup_file(tdb_file);
	if (retval)
		goto errout;
	printf("Overwriting existing filesystem; this can be undone "
		"using the command:\n"
		"    e2undo %s %s\n\n", tdb_file, device_name);

	free(tdb_file);
	return 0;
errout:
	free(tdb_file);
err:
	com_err("checkMD", retval, "while trying to setup undo file\n");
	return retval;
}

static void open_filesystem(char *device, int open_flags, blk64_t superblock,
			    blk64_t blocksize, int catastrophic,
			    char *data_filename, char *undo_file,
				char *mnt_pt)
{
	int	retval;
	io_channel data_io = 0;
	io_manager io_ptr = unix_io_manager;

	if (superblock != 0 && blocksize == 0) {
		com_err(device, 0, "if you specify the superblock, you must also specify the block size");
		current_fs = NULL;
		return;
	}

	if (data_filename) {
		if ((open_flags & EXT2_FLAG_IMAGE_FILE) == 0) {
			com_err(device, 0,
				"The -d option is only valid when reading an e2image file");
			current_fs = NULL;
			return;
		}
		retval = unix_io_manager->open(data_filename, 0, &data_io);
		if (retval) {
			com_err(data_filename, 0, "while opening data source");
			current_fs = NULL;
			return;
		}
	}

	if (catastrophic && (open_flags & EXT2_FLAG_RW)) {
		com_err(device, 0,
			"opening read-only because of catastrophic mode");
		open_flags &= ~EXT2_FLAG_RW;
	}
	if (catastrophic)
		open_flags |= EXT2_FLAG_SKIP_MMP;

	if (undo_file) {
		retval = debugfs_setup_tdb(device, undo_file, &io_ptr);
		if (retval)
			exit(1);
	}

	//printf("1%s 2%d 3%llu 4%llu \n", device, open_flags, superblock, blocksize);
    if (mnt_pt) {
        fdDev = open(mnt_pt, O_RDONLY);
        retval = ioctl(fdDev, FIFREEZE, 0);
        if (retval) {
            com_err(device, retval, "freezing filesystem failed");
            return;
        }
    }
    g_open_flags = open_flags;

	retval = ext2fs_open(device, open_flags, superblock, blocksize,
			     io_ptr, &current_fs);
	if (retval) {
		com_err(device, retval, "while opening filesystem");
		if (retval == EXT2_ET_BAD_MAGIC)
			check_plausibility(device, CHECK_FS_EXIST, NULL);
		current_fs = NULL;
		return;
	}
	current_fs->default_bitmap_type = EXT2FS_BMAP64_RBTREE;

	if (catastrophic)
		com_err(device, 0, "catastrophic mode - not reading inode or group bitmaps");
	else {
		retval = ext2fs_read_inode_bitmap(current_fs);
		if (retval) {
			com_err(device, retval, "while reading inode bitmap");
			goto errout;
		}
		retval = ext2fs_read_block_bitmap(current_fs);
		if (retval) {
			com_err(device, retval, "while reading block bitmap");
			goto errout;
		}
	}

	if (data_io) {
		retval = ext2fs_set_data_io(current_fs, data_io);
		if (retval) {
			com_err(device, retval,
				"while setting data source");
			goto errout;
		}
	}

	root = cwd = EXT2_ROOT_INO;
	return;

errout:
	if (fdDev) {
		retval = ioctl(fdDev, FITHAW, 0);
		if (retval)
			com_err(device, retval, "thaw filesystem failed");
	}

	retval = ext2fs_close_free(&current_fs);
	if (retval)
		com_err(device, retval, "while trying to close filesystem");
}

void do_open_filesys(int argc, char **argv)
{
	int	c, err;
	int	catastrophic = 0;
	blk64_t	superblock = 0;
	blk64_t	blocksize = 0;
	int	open_flags = EXT2_FLAG_SOFTSUPP_FEATURES | EXT2_FLAG_64BITS; 
	char	*data_filename = 0;
	char	*undo_file = NULL;
	char 	*mnt_pt = NULL;

	reset_getopt();
	while ((c = getopt(argc, argv, "iwfecb:s:d:Dz:m:")) != EOF) {
		switch (c) {
		case 'i':
			open_flags |= EXT2_FLAG_IMAGE_FILE;
			break;
		case 'w':
#ifdef READ_ONLY
			goto print_usage;
#else
			open_flags |= EXT2_FLAG_RW;
#endif /* READ_ONLY */
			break;
		case 'f':
			open_flags |= EXT2_FLAG_FORCE;
			break;
		case 'e':
			open_flags |= EXT2_FLAG_EXCLUSIVE;
			break;
		case 'c':
			catastrophic = 1;
			break;
		case 'd':
			data_filename = optarg;
			break;
		case 'm':
			mnt_pt = optarg;
			break;
		case 'D':
			open_flags |= EXT2_FLAG_DIRECT_IO;
			break;
		case 'b':
			blocksize = parse_ulong(optarg, argv[0],
						"block size", &err);
			if (err)
				return;
			break;
		case 's':
			err = strtoblk(argv[0], optarg,
				       "superblock block number", &superblock);
			if (err)
				return;
			break;
		case 'z':
			undo_file = optarg;
			break;
		default:
			goto print_usage;
		}
	}
	if (optind != argc-1) {
		goto print_usage;
	}
	if (check_fs_not_open(argv[0]))
		return;
	open_filesystem(argv[optind], open_flags,
			superblock, blocksize, catastrophic,
			data_filename, undo_file, mnt_pt);
	return;

print_usage:
	fprintf(stderr, "%s: Usage: open [-s superblock][-m mnt_point] [-b blocksize] "
		"[-d image_filename] [-c] [-i] [-f] [-e] [-D] "
#ifndef READ_ONLY
		"[-w] "
#endif
		"<device>\n", argv[0]);
}



static void close_filesystem(NOARGS)
{
	int	retval;
	g_open_flags = 0;

	if (fdDev) {
        retval = ioctl(fdDev, FITHAW, 0);
        if (retval)
            com_err("thaw filesystem failed", retval, 0);
        fdDev = 0;
    }

	if (current_fs->flags & EXT2_FLAG_IB_DIRTY) {
		retval = ext2fs_write_inode_bitmap(current_fs);
		if (retval)
			com_err("ext2fs_write_inode_bitmap", retval, 0);
	}
	if (current_fs->flags & EXT2_FLAG_BB_DIRTY) {
		retval = ext2fs_write_block_bitmap(current_fs);
		if (retval)
			com_err("ext2fs_write_block_bitmap", retval, 0);
	}
	if (current_qctx)
		quota_release_context(&current_qctx);
	retval = ext2fs_close_free(&current_fs);
	if (retval)
		com_err("ext2fs_close", retval, 0);
	return;
}

void do_close_filesys(int argc, char **argv)
{
	int	c;

	if (check_fs_open(argv[0]))
		return;

	reset_getopt();
	while ((c = getopt (argc, argv, "a")) != EOF) {
		switch (c) {
		case 'a':
			current_fs->flags &= ~EXT2_FLAG_MASTER_SB_ONLY;
			break;
		default:
			goto print_usage;
		}
	}

	if (argc > optind) {
	print_usage:
		com_err(0, 0, "Usage: close_filesys [-a]");
		return;
	}

	close_filesystem();
}





static void print_bg_opts(ext2_filsys fs, dgrp_t group, int mask,
			  const char *str, int *first, FILE *f)
{
	if (ext2fs_bg_flags_test(fs, group, mask)) {
		if (*first) {
			fputs("           [", f);
			*first = 0;
		} else
			fputs(", ", f);
		fputs(str, f);
	}
}

static void do_write_bd(struct ext4_group_desc *buf, FILE *fd) {
    fprintf(fd," Blocks bitmap block                %u	  \n",buf->bg_block_bitmap);
    fprintf(fd," Inodes bitmap block                %u	  \n",buf->bg_inode_bitmap);
    fprintf(fd," Inodes table block                 %u	  \n",buf->bg_inode_table);
    fprintf(fd," Free blocks count                  %hu	  \n",buf->bg_free_blocks_count);
    fprintf(fd," Free inodes count                  %hu	  \n",buf->bg_free_inodes_count);
    fprintf(fd," Directories count                  %hu	  \n",buf->bg_used_dirs_count);
    fprintf(fd," EXT4_BG_flags(INODE_UNINIT, etc)  %hu	  \n",buf->bg_flags);
    fprintf(fd," Exclude bitmap for snapshots       %u	  \n",buf->bg_exclude_bitmap_lo);
    fprintf(fd," crc32(s_uuid+grp_num+bitmap) LSB  %hu	  \n",buf->bg_block_bitmap_csum_lo);
    fprintf(fd," crc32(s_uuid+grp_num+bitmap) LSB  %hu	  \n",buf->bg_inode_bitmap_csum_lo);
    fprintf(fd," Unused inodes count               %hu	  \n",buf->bg_itable_unused);
    fprintf(fd," crc16(sb_uuid+group+desc)         %hu	  \n",buf->bg_checksum);
    fprintf(fd," Blocks bitmap block MSB            %u	  \n",buf->bg_block_bitmap_hi);
    fprintf(fd," Inodes bitmap block MSB            %u	  \n",buf->bg_inode_bitmap_hi);
    fprintf(fd," Inodes table block MSB             %u	  \n",buf->bg_inode_table_hi);
    fprintf(fd," Free blocks count MSB              %hu  \n",buf->bg_free_blocks_count_hi);
    fprintf(fd," Free inodes count MSB              %hu  \n",buf->bg_free_inodes_count_hi);
    fprintf(fd," Directories count MSB              %hu  \n",buf->bg_used_dirs_count_hi);
    fprintf(fd," Unused inodes count MSB            %hu  \n",buf->bg_itable_unused_hi);
    fprintf(fd," Exclude bitmap block MSB           %u	 \n ",buf->bg_exclude_bitmap_hi);
    fprintf(fd," crc32(s_uuid+grp_num+bitmap) MSB  %hu	 \n ",buf->bg_block_bitmap_csum_hi);
    fprintf(fd," crc32(s_uuid+grp_num+bitmap) MSB  %hu	 \n",buf->bg_inode_bitmap_csum_hi);
    fprintf(fd," reserved                           %u	 \n",buf->bg_reserved);
}

static void do_write_sb(struct ext2_super_block *sb, FILE *fd, int redundant) {
	if (redundant == 0) {
		fprintf(fd, "**********************\n");
		fprintf(fd, "*original super block*\n");
		fprintf(fd, "**********************\n");

		list_super2(sb, fd);

	} else if (redundant == 1) {
		fprintf(fd, "***********************\n");
		fprintf(fd, "*redundant super block*\n");
		fprintf(fd, "***********************\n");

		list_super2(sb, fd);
	}
}

static void do_write_inode(struct ext2_inode *inode, FILE *fd) {
	 fprintf(fd," File mode                   %hu	  \n",inode->i_mode);
	 fprintf(fd," Low 16 bits of Owner Uid    %hu	  \n",inode->i_uid);
	 fprintf(fd," Size in bytes               %u	  \n",inode->i_size);
	 fprintf(fd," Access time                 %u	  \n",inode->i_atime);
	 fprintf(fd," Inode change time           %u	  \n",inode->i_ctime);
	 fprintf(fd," Modification time           %u	  \n",inode->i_mtime);
	 fprintf(fd," Deletion Time               %u	  \n",inode->i_dtime);
	 fprintf(fd," Low 16 bits of Group Id     %hu	  \n",inode->i_gid);
	 fprintf(fd," Links count                 %hu	  \n",inode->i_links_count);
	 fprintf(fd," Blocks count                %u	  \n",inode->i_blocks);
	 fprintf(fd," File flags                  %u	  \n",inode->i_flags);

	 fprintf(fd," Version                     %u	  \n",inode->osd1.linux1.l_i_version);
	 fprintf(fd," Translator                  %u	  \n",inode->osd1.hurd1.h_i_translator);

	 fprintf(fd," Pointers to blocks          %u	  \n",inode->i_block[EXT2_N_BLOCKS]);
	 fprintf(fd," File version (for NFS)      %u	  \n",inode->i_generation);
	 fprintf(fd," File ACL                    %u	  \n",inode->i_file_acl);
	 fprintf(fd," Formerly i_dir_acl, directory ACL  %u	  \n",inode->i_size_high);
	 fprintf(fd," Fragment address            %u	  \n",inode->i_faddr);

	 fprintf(fd, "Block count: %llu\n",
	 			(((unsigned long long)
	 			  inode->osd2.linux2.l_i_blocks_hi << 32)) +
	 			inode->i_blocks);

	 fprintf(fd, "File ACL: %llu",
	 			inode->i_file_acl | ((long long)
	 				(inode->osd2.linux2.l_i_file_acl_high) << 32));

	 fprintf(fd," these 2 fields             %hu	  \n",inode->osd2.linux2.l_i_uid_high);
	 fprintf(fd," were reserved2[0]          %hu	  \n",inode->osd2.linux2.l_i_gid_high);
	 fprintf(fd," crc32c(uuid+inum+inode)    %hu	  \n",inode->osd2.linux2.l_i_checksum_lo);
	 fprintf(fd," reserved                   %hu	  \n",inode->osd2.linux2.l_i_reserved);
	 fprintf(fd," Fragment number            %hu	  \n",inode->osd2.hurd2.h_i_frag);
	 fprintf(fd," Fragment size              %hu	  \n",inode->osd2.hurd2.h_i_fsize);
	 fprintf(fd," mode_high                  %hu	  \n",inode->osd2.hurd2.h_i_mode_high);
	 fprintf(fd," uid_high                   %hu	  \n",inode->osd2.hurd2.h_i_uid_high);
	 fprintf(fd," gid_high                   %hu	  \n",inode->osd2.hurd2.h_i_gid_high);
	 fprintf(fd," author                     %u	  \n",inode->osd2.hurd2.h_i_author);
}


static void do_write_bitmap(unsigned int *buf, FILE *fd, long lSize) {
	int count = 0;
	for (int i = 0; i < lSize; i++) {
		if (*buf & 1 == 1) { // confirm whether the lowest bit is 1
			count++;
			fprintf(fd, "Index:%d OCCUPIED \n", i);
		} else {
			fprintf(fd, "Index:%d FREE \n", i);
		}
		*buf >>= 1; // next bit
	}
	fprintf(fd, "OCCUPIED/TOTAL = %d / %ld	  \n", count, lSize);
}


static void do_write_journal(struct journal_superblock_s *buf, FILE *fd) {

	fprintf(fd, " journal's header \n");
	fprintf(fd, " h_magic          %u	  \n", buf->s_header.h_magic);
	fprintf(fd, " h_blocktype      %u	  \n", buf->s_header.h_blocktype);
	fprintf(fd, " h_sequence       %u	  \n", buf->s_header.h_sequence);

	fprintf(fd, " Static information describing the journal \n");
	fprintf(fd, " journal device blocksize          %u	  \n",
			buf->s_blocksize);
	fprintf(fd, " total blocks in journal file      %u	  \n", buf->s_maxlen);
	fprintf(fd, " first block of log information    %u	  \n", buf->s_first);
	fprintf(fd,
			" Dynamic information describing the current state of the log \n");
	fprintf(fd, " first commit ID expected in log   %u	  \n", buf->s_sequence);
	fprintf(fd, " blocknr of start of log           %u	  \n", buf->s_start);

	//jfs_dat.h

}

void do_analyze_meta_data(int argc, char *argv[]) {
    char *path = argv[1];
    DIR * dd;
    FILE *fd;
    FILE *nfd;
    struct dirent* dir_ent;

    long lSize;
    //unsigned int *buf = malloc (1024);
    unsigned int *buf;
    size_t size;
    unsigned int length;
    int bd_loop = 0;
    int sb_loop = 0;
    int journal_loop = 0;

    dd = opendir(path);

    if (!dd) {
		com_err(__func__, 0, "directory open failed");
        return;
    }

    if (chdir(path)) {
		com_err(__func__, 0, "change dir failed");
        return;
    }

   if (strstr(path, "/bd/"))
        bd_loop = 1;
   else if (strstr(path,"/sb/"))
        sb_loop = 1;
   else if (strstr(path, "/journal/"))
	   journal_loop = 1;

    while ((dir_ent = readdir(dd)) && dir_ent) {
        if (!strcmp (dir_ent->d_name, "."))
            continue;

        if (!strcmp (dir_ent->d_name, ".."))
            continue;

		if (strstr(dir_ent->d_name, ".bin")) {

			fd = fopen(dir_ent->d_name, "rb");
			// obtain file size:
			fseek(fd, 0, SEEK_END);
			lSize = ftell(fd);
			rewind(fd);

			// allocate memory to contain the whole file:
			buf = malloc(lSize);
			if (buf == NULL) {
				fputs("Memory error", stderr);
				exit(2);
			}

			if (fd) {
				// size = fread(buf, 1024,  1, fd);
				size = fread(buf, lSize, 1, fd);
				fclose(fd);
			}

            length = strlen(dir_ent->d_name);
            dir_ent->d_name[length - 4] ='\0';
            sprintf(dir_ent->d_name,  "%s.txt", dir_ent->d_name);

            nfd = fopen(dir_ent->d_name, "w");
            if (nfd) {
				if (bd_loop) {
					if (strstr(dir_ent->d_name, "bd")){
						// write block
						do_write_bd((struct ext4_group_desc *) buf, nfd);
					}
					else if (strstr(dir_ent->d_name, "bbitmap")){
						do_write_bitmap(buf,nfd,lSize);
					}
					else if (strstr(dir_ent->d_name, "ibitmap")){
						do_write_bitmap(buf,nfd,lSize);
					}
					else if (strstr(dir_ent->d_name, "itable")){
						do_write_inode((struct ext2_inode *)buf, nfd);
					}
					/*
					else if (strstr(dir_ent->d_name, "rgdt")){
					}
					*/
				}
                else if(sb_loop){
                	if (lSize < 1024) {
                		fputs("super block size shouldn't < 1024 KB", stderr);
                		exit(2);
                	}

                	// write original super block
                	do_write_sb ((struct ext2_super_block *)buf, nfd, 0);
                	int *next_buf;
                	for(int i = 1; i < lSize/1024; i++){
                		// write redundant super blocks
                		next_buf = buf + 1024;
                		do_write_sb ((struct ext2_super_block *) next_buf, nfd, 1);
                	}


                }
                else if(journal_loop){
                	// write journal
                	do_write_journal((struct journal_superblock_s *)buf, nfd);
                }

                fclose(nfd);
            }
        }
    }

    if (buf)
        free(buf);
}

void do_extract_meta_data(int argc, char *argv[])
{
    unsigned long i, block_size;
    blk64_t super_blk;
    blk64_t old_desc_blk;
    blk64_t old_desc_blocks;
    blk64_t blk;
    unsigned long size = 1;
	unsigned long int *buf = malloc(current_fs->group_desc_count * sizeof(blk64_t));
	unsigned long int *inode_buf = malloc(current_fs->blocksize * current_fs->inode_blocks_per_group);
    struct stat st = {0};
    FILE *fp;
    char *dev = &argv[1][4];
    char suffix[100];
    int suffix_len = 0;
	io_manager io_ptr = unix_io_manager;
    struct ext4_group_desc *desc;
	struct ext2_inode_large inode;
	ext2_inode_scan	scan;
	errcode_t	retval;
	ext2_ino_t	ino;
    int inode_size = sizeof(struct ext2_inode);
    int escape = 0;
	int block_nbytes = EXT2_CLUSTERS_PER_GROUP(current_fs->super) / 8;
	int inode_nbytes = EXT2_INODES_PER_GROUP(current_fs->super) / 8;

	int csum_flag;
    int check;
    static journal_t *journal = NULL;
    unsigned long long blocknr;
    struct buffer_head *bh;

    if (argc < 3) {
        printf("Minimum expected arguments are device and path for copying metadata\n");
        goto ret;
    }

	if (EXT2_INODE_SIZE(current_fs->super) > EXT2_GOOD_OLD_INODE_SIZE)
		inode_size = sizeof(struct ext2_inode_large);

    sprintf(suffix, "%s%s",argv[2],dev);
    suffix_len = strlen(suffix);
    reset_getopt();

    buf[0] = 0;
    block_size = EXT2_BLOCK_SIZE(current_fs->super);

    if (stat(suffix, &st) == -1) {
        mkdir(suffix, 0777);
    }


    sprintf(suffix, "%s/sb",suffix);
    if (stat(suffix, &st) == -1) {
        mkdir(suffix, 0777);
    }

    suffix[suffix_len] = '\0';

    sprintf(suffix, "%s/bd",suffix);
    if (stat(suffix, &st) == -1) {
        mkdir(suffix, 0777);
    }

    suffix[suffix_len] = '\0';

    sprintf(suffix, "%s/journal",suffix);
    if (stat(suffix, &st) == -1) {
        mkdir(suffix, 0777);
    }


	if (ext2fs_has_feature_meta_bg(current_fs->super))
		old_desc_blocks = current_fs->super->s_first_meta_bg;
	else
		old_desc_blocks = current_fs->desc_blocks;

    for (i = 0; i < current_fs->group_desc_count; i++) {
        super_blk = 0;
        ext2fs_super_and_bgd_loc2(current_fs, i, &super_blk, &old_desc_blk, NULL, NULL);
        if (super_blk) {
            buf[size] = super_blk;
            size++;
        }


        desc = (struct ext4_group_desc *) ext2fs_group_desc(current_fs, current_fs->group_desc, i);

        suffix[suffix_len] = '\0';
        sprintf(suffix, "%s/bd/bd%lu.bin", suffix, i);

        fp = fopen(suffix, "wb");

        //fwrite(desc, sizeof(struct ext4_group_desc), 1, fp);
        //if after 32 bytes then ignore
        fwrite(desc, sizeof(struct ext4_group_desc) / 2, 1, fp);

        fclose(fp);


/*
        if (old_desc_blk) {
            retval = io_channel_read_blk64(current_fs->io, old_desc_blk + old_desc_blocks,
                    current_fs->super->s_reserved_gdt_blocks, inode_buf);
            if (retval) {
                retval = EXT2_ET_SHORT_READ;
                goto ret;
            }
            suffix[suffix_len] = '\0';
            sprintf(suffix, "%s/bd/rgdt%lu.bin", suffix, i);

            fp = fopen(suffix, "wb");

            fwrite(inode_buf, block_size * current_fs->super->s_reserved_gdt_blocks, 1, fp);

            fclose(fp);
        }
*/

        blk = desc->bg_block_bitmap |
            (ext2fs_has_feature_64bit(current_fs->super) ?
             (__u64) desc->bg_block_bitmap_hi << 32 : 0);

        if (desc->bg_flags & EXT2_BG_BLOCK_UNINIT)
            memset(inode_buf, 0, block_nbytes);
        else {
            retval = io_channel_read_blk64(current_fs->io, blk,
                    1, inode_buf);
            if (retval) {
                retval = EXT2_ET_BLOCK_BITMAP_READ;
                goto ret;
            }

        }

        suffix[suffix_len] = '\0';
        sprintf(suffix, "%s/bd/bbitmap%lu.bin", suffix, i);

        fp = fopen(suffix, "wb");
        fwrite(inode_buf, block_nbytes, 1, fp);

        fclose(fp);


        blk =  desc->bg_inode_table |
            (ext2fs_has_feature_64bit(current_fs->super) ?
             (__u64) desc->bg_inode_table_hi << 32 : 0);
        if (!blk) {
            retval = EXT2_ET_MISSING_INODE_TABLE;
            goto ret;
        }

        if (desc->bg_flags & EXT2_BG_INODE_UNINIT || desc->bg_flags & EXT2_BG_INODE_ZEROED) {
            memset(inode_buf, 0x0,  current_fs->blocksize * current_fs->inode_blocks_per_group);
        } else {
            retval = io_channel_read_blk64(current_fs->io, blk, current_fs->inode_blocks_per_group, inode_buf);
            if (retval) {
                retval = EXT2_ET_SHORT_READ;
                goto ret;
            }
        }
        suffix[suffix_len] = '\0';
        sprintf(suffix, "%s/bd/itable%lu.bin", suffix, i);

        fp = fopen(suffix, "wb");
        fwrite(inode_buf, current_fs->blocksize * current_fs->inode_blocks_per_group, 1, fp);

        fclose(fp);

        blk = desc->bg_inode_bitmap |
            (ext2fs_has_feature_64bit(current_fs->super) ?
             (__u64) desc->bg_inode_bitmap_hi << 32 : 0);


        if (desc->bg_flags & EXT2_BG_INODE_UNINIT)
            memset(inode_buf, 0, inode_nbytes);
        else {
            retval = io_channel_read_blk64(current_fs->io, blk,
                    1, inode_buf);
            if (retval) {
                retval = EXT2_ET_INODE_BITMAP_READ;
                goto ret;
            }

        }

        suffix[suffix_len] = '\0';
        sprintf(suffix, "%s/bd/ibitmap%lu.bin", suffix, i);

        fp = fopen(suffix, "wb");

        fwrite(inode_buf, inode_nbytes, 1, fp);

        fclose(fp);

    }

    suffix[suffix_len] = '\0';
    sprintf(suffix, "%s/journal/journal.bin", suffix);
    fp = fopen(suffix, "wb");
	retval = ext2fs_open_journal(current_fs, &journal);
	if (retval)
		goto ret;
    for (i = 0; i < journal->j_maxlen; i++) {

	    retval = journal_bmap(journal, i, &blocknr);
	    if (retval)
		    goto ret;

	    bh = getblk(journal->j_dev, blocknr, journal->j_blocksize);
        if (!bh) {
            retval = EXT2_ET_BAD_BLOCK_IN_INODE_TABLE;
            goto ret;
        }

	    mark_buffer_uptodate(bh, 0);
		ll_rw_block(READ, 1, &bh);
		retval = bh->b_err;
		if (retval) {
	        ext2fs_free_mem(&bh);
			goto ret;
		}

        fwrite(bh->b_data, journal->j_blocksize, 1, fp);
	    ext2fs_free_mem(&bh);
    }
	ext2fs_close_journal(current_fs, &journal);
    fclose(fp);


    suffix[suffix_len] = '\0';
    sprintf(suffix, "%s/sb/sb.bin", suffix);
    fp = fopen(suffix, "wb");
    for (i = 0; i < size; i++) {

	    ext2fs_open(argv[1], g_open_flags, buf[i], block_size,
			     io_ptr, &current_fs);

        fwrite(current_fs->super, sizeof(struct ext2_super_block), 1, fp);
    }
    fclose(fp);
ret:
    if (buf)
        free(buf);
    if (inode_buf)
        free(inode_buf);

}

void do_show_super_stats(int argc, char *argv[])
{
	const char *units ="block";
	dgrp_t	i;
	FILE 	*out;
	int	c, header_only = 0;
	int	numdirs = 0, first, gdt_csum;

	reset_getopt();
	while ((c = getopt (argc, argv, "h")) != EOF) {
		switch (c) {
		case 'h':
			header_only++;
			break;
		default:
			goto print_usage;
		}
	}
	if (optind != argc) {
		goto print_usage;
	}
	if (check_fs_open(argv[0]))
		return;
	out = open_pager();

	if (ext2fs_has_feature_bigalloc(current_fs->super))
		units = "cluster";

	list_super2(current_fs->super, out);
	for (i=0; i < current_fs->group_desc_count; i++)
		numdirs += ext2fs_bg_used_dirs_count(current_fs, i);
	fprintf(out, "Directories:              %d\n", numdirs);

	if (header_only) {
		close_pager(out);
		return;
	}

	gdt_csum = ext2fs_has_group_desc_csum(current_fs);
	for (i = 0; i < current_fs->group_desc_count; i++) {
		fprintf(out, " Group %2d: block bitmap at %llu, "
		        "inode bitmap at %llu, "
		        "inode table at %llu\n"
		        "           %u free %s%s, "
		        "%u free %s, "
		        "%u used %s%s",
		        i, ext2fs_block_bitmap_loc(current_fs, i),
		        ext2fs_inode_bitmap_loc(current_fs, i),
			ext2fs_inode_table_loc(current_fs, i),
		        ext2fs_bg_free_blocks_count(current_fs, i), units,
		        ext2fs_bg_free_blocks_count(current_fs, i) != 1 ?
			"s" : "",
		        ext2fs_bg_free_inodes_count(current_fs, i),
		        ext2fs_bg_free_inodes_count(current_fs, i) != 1 ?
			"inodes" : "inode",
		        ext2fs_bg_used_dirs_count(current_fs, i),
		        ext2fs_bg_used_dirs_count(current_fs, i) != 1 ? "directories"
 				: "directory", gdt_csum ? ", " : "\n");
		if (gdt_csum)
			fprintf(out, "%u unused %s\n",
				ext2fs_bg_itable_unused(current_fs, i),
				ext2fs_bg_itable_unused(current_fs, i) != 1 ?
				"inodes" : "inode");
		first = 1;
		print_bg_opts(current_fs, i, EXT2_BG_INODE_UNINIT, "Inode not init",
			      &first, out);
		print_bg_opts(current_fs, i, EXT2_BG_BLOCK_UNINIT, "Block not init",
			      &first, out);
		if (gdt_csum) {
			fprintf(out, "%sChecksum 0x%04x",
				first ? "           [":", ", ext2fs_bg_checksum(current_fs, i));
			first = 0;
		}
		if (!first)
			fputs("]\n", out);
	}
	close_pager(out);
	return;
print_usage:
	fprintf(stderr, "%s: Usage: show_super [-h]\n", argv[0]);
}



struct list_blocks_struct {
	FILE		*f;
	e2_blkcnt_t	total;
	blk64_t		first_block, last_block;
	e2_blkcnt_t	first_bcnt, last_bcnt;
	e2_blkcnt_t	first;
};

static void finish_range(struct list_blocks_struct *lb)
{
	if (lb->first_block == 0)
		return;
	if (lb->first)
		lb->first = 0;
	else
		fprintf(lb->f, ", ");
	if (lb->first_block == lb->last_block)
		fprintf(lb->f, "(%lld):%llu",
			(long long)lb->first_bcnt, lb->first_block);
	else
		fprintf(lb->f, "(%lld-%lld):%llu-%llu",
			(long long)lb->first_bcnt, (long long)lb->last_bcnt,
			lb->first_block, lb->last_block);
	lb->first_block = 0;
}

static int list_blocks_proc(ext2_filsys fs EXT2FS_ATTR((unused)),
			    blk64_t *blocknr, e2_blkcnt_t blockcnt,
			    blk64_t ref_block EXT2FS_ATTR((unused)),
			    int ref_offset EXT2FS_ATTR((unused)),
			    void *private)
{
	struct list_blocks_struct *lb = (struct list_blocks_struct *) private;

	lb->total++;
	if (blockcnt >= 0) {
		/*
		 * See if we can add on to the existing range (if it exists)
		 */
		if (lb->first_block &&
		    (lb->last_block+1 == *blocknr) &&
		    (lb->last_bcnt+1 == blockcnt)) {
			lb->last_block = *blocknr;
			lb->last_bcnt = blockcnt;
			return 0;
		}
		/*
		 * Start a new range.
		 */
		finish_range(lb);
		lb->first_block = lb->last_block = *blocknr;
		lb->first_bcnt = lb->last_bcnt = blockcnt;
		return 0;
	}
	/*
	 * Not a normal block.  Always force a new range.
	 */
	finish_range(lb);
	if (lb->first)
		lb->first = 0;
	else
		fprintf(lb->f, ", ");
	if (blockcnt == -1)
		fprintf(lb->f, "(IND):%llu", (unsigned long long) *blocknr);
	else if (blockcnt == -2)
		fprintf(lb->f, "(DIND):%llu", (unsigned long long) *blocknr);
	else if (blockcnt == -3)
		fprintf(lb->f, "(TIND):%llu", (unsigned long long) *blocknr);
	return 0;
}

static void internal_dump_inode_extra(FILE *out,
				      const char *prefix EXT2FS_ATTR((unused)),
				      ext2_ino_t inode_num EXT2FS_ATTR((unused)),
				      struct ext2_inode_large *inode)
{
	fprintf(out, "Size of extra inode fields: %u\n", inode->i_extra_isize);
	if (inode->i_extra_isize > EXT2_INODE_SIZE(current_fs->super) -
			EXT2_GOOD_OLD_INODE_SIZE) {
		fprintf(stderr, "invalid inode->i_extra_isize (%u)\n",
				inode->i_extra_isize);
		return;
	}
}

static void dump_blocks(FILE *f, const char *prefix, ext2_ino_t inode)
{
	struct list_blocks_struct lb;

	fprintf(f, "%sBLOCKS:\n%s", prefix, prefix);
	lb.total = 0;
	lb.first_block = 0;
	lb.f = f;
	lb.first = 1;
	ext2fs_block_iterate3(current_fs, inode, BLOCK_FLAG_READ_ONLY, NULL,
			      list_blocks_proc, (void *)&lb);
	finish_range(&lb);
	if (lb.total)
		fprintf(f, "\n%sTOTAL: %lld\n", prefix, (long long)lb.total);
	fprintf(f,"\n");
}


#define DUMP_LEAF_EXTENTS	0x01
#define DUMP_NODE_EXTENTS	0x02
#define DUMP_EXTENT_TABLE	0x04

static void dump_extents(FILE *f, const char *prefix, ext2_ino_t ino,
			 int flags, int logical_width, int physical_width)
{
	ext2_extent_handle_t	handle;
	struct ext2fs_extent	extent;
	struct ext2_extent_info info;
	int			op = EXT2_EXTENT_ROOT;
	unsigned int		printed = 0;
	errcode_t 		errcode;

	errcode = ext2fs_extent_open(current_fs, ino, &handle);
	if (errcode)
		return;

	if (flags & DUMP_EXTENT_TABLE)
		fprintf(f, "Level Entries %*s %*s Length Flags\n",
			(logical_width*2)+3, "Logical",
			(physical_width*2)+3, "Physical");
	else
		fprintf(f, "%sEXTENTS:\n%s", prefix, prefix);

	while (1) {
		errcode = ext2fs_extent_get(handle, op, &extent);

		if (errcode)
			break;

		op = EXT2_EXTENT_NEXT;

		if (extent.e_flags & EXT2_EXTENT_FLAGS_SECOND_VISIT)
			continue;

		if (extent.e_flags & EXT2_EXTENT_FLAGS_LEAF) {
			if ((flags & DUMP_LEAF_EXTENTS) == 0)
				continue;
		} else {
			if ((flags & DUMP_NODE_EXTENTS) == 0)
				continue;
		}

		errcode = ext2fs_extent_get_info(handle, &info);
		if (errcode)
			continue;

		if (!(extent.e_flags & EXT2_EXTENT_FLAGS_LEAF)) {
			if (extent.e_flags & EXT2_EXTENT_FLAGS_SECOND_VISIT)
				continue;

			if (flags & DUMP_EXTENT_TABLE) {
				fprintf(f, "%2d/%2d %3d/%3d %*llu - %*llu "
					"%*llu%*s %6u\n",
					info.curr_level, info.max_depth,
					info.curr_entry, info.num_entries,
					logical_width,
					extent.e_lblk,
					logical_width,
					extent.e_lblk + (extent.e_len - 1),
					physical_width,
					extent.e_pblk,
					physical_width+3, "", extent.e_len);
				continue;
			}

			fprintf(f, "%s(ETB%d):%lld",
				printed ? ", " : "", info.curr_level,
				extent.e_pblk);
			printed = 1;
			continue;
		}

		if (flags & DUMP_EXTENT_TABLE) {
			fprintf(f, "%2d/%2d %3d/%3d %*llu - %*llu "
				"%*llu - %*llu %6u %s\n",
				info.curr_level, info.max_depth,
				info.curr_entry, info.num_entries,
				logical_width,
				extent.e_lblk,
				logical_width,
				extent.e_lblk + (extent.e_len - 1),
				physical_width,
				extent.e_pblk,
				physical_width,
				extent.e_pblk + (extent.e_len - 1),
				extent.e_len,
				extent.e_flags & EXT2_EXTENT_FLAGS_UNINIT ?
					"Uninit" : "");
			continue;
		}

		if (extent.e_len == 0)
			continue;
		else if (extent.e_len == 1)
			fprintf(f,
				"%s(%lld%s):%lld",
				printed ? ", " : "",
				extent.e_lblk,
				extent.e_flags & EXT2_EXTENT_FLAGS_UNINIT ?
				"[u]" : "",
				extent.e_pblk);
		else
			fprintf(f,
				"%s(%lld-%lld%s):%lld-%lld",
				printed ? ", " : "",
				extent.e_lblk,
				extent.e_lblk + (extent.e_len - 1),
				extent.e_flags & EXT2_EXTENT_FLAGS_UNINIT ?
					"[u]" : "",
				extent.e_pblk,
				extent.e_pblk + (extent.e_len - 1));
		printed = 1;
	}
	if (printed)
		fprintf(f, "\n");
	ext2fs_extent_free(handle);
}

static void dump_inline_data(FILE *out, const char *prefix, ext2_ino_t inode_num)
{
	errcode_t retval;
	size_t size;

	retval = ext2fs_inline_data_size(current_fs, inode_num, &size);
	if (!retval)
		fprintf(out, "%sSize of inline data: %zu\n", prefix, size);
}

static void dump_fast_link(FILE *out, ext2_ino_t inode_num,
			   struct ext2_inode *inode, const char *prefix)
{
	errcode_t retval = 0;
	char *buf;
	size_t size;

	if (inode->i_flags & EXT4_INLINE_DATA_FL) {
		retval = ext2fs_inline_data_size(current_fs, inode_num, &size);
		if (retval)
			goto out;

		retval = ext2fs_get_memzero(size + 1, &buf);
		if (retval)
			goto out;

		retval = ext2fs_inline_data_get(current_fs, inode_num,
						inode, buf, &size);
		if (retval)
			goto out;
		fprintf(out, "%sFast link dest: \"%.*s\"\n", prefix,
			(int)size, buf);

		retval = ext2fs_free_mem(&buf);
		if (retval)
			goto out;
	} else {
		size_t sz = EXT2_I_SIZE(inode);

		if (sz > sizeof(inode->i_block))
			sz = sizeof(inode->i_block);
		fprintf(out, "%sFast link dest: \"%.*s\"\n", prefix, (int) sz,
			(char *)inode->i_block);
	}
out:
	if (retval)
		com_err(__func__, retval, "while dumping link destination");
}

void internal_dump_inode(FILE *out, const char *prefix,
			 ext2_ino_t inode_num, struct ext2_inode *inode,
			 int do_dump_blocks)
{
	const char *i_type;
	char frag, fsize;
	int os = current_fs->super->s_creator_os;
	struct ext2_inode_large *large_inode;
	int is_large_inode = 0;

	if (EXT2_INODE_SIZE(current_fs->super) > EXT2_GOOD_OLD_INODE_SIZE)
		is_large_inode = 1;
	large_inode = (struct ext2_inode_large *) inode;

	if (LINUX_S_ISDIR(inode->i_mode)) i_type = "directory";
	else if (LINUX_S_ISREG(inode->i_mode)) i_type = "regular";
	else if (LINUX_S_ISLNK(inode->i_mode)) i_type = "symlink";
	else if (LINUX_S_ISBLK(inode->i_mode)) i_type = "block special";
	else if (LINUX_S_ISCHR(inode->i_mode)) i_type = "character special";
	else if (LINUX_S_ISFIFO(inode->i_mode)) i_type = "FIFO";
	else if (LINUX_S_ISSOCK(inode->i_mode)) i_type = "socket";
	else i_type = "bad type";
	fprintf(out, "%sInode: %u   Type: %s    ", prefix, inode_num, i_type);
	fprintf(out, "%sMode:  %04o   Flags: 0x%x\n",
		prefix, inode->i_mode & 0777, inode->i_flags);
	if (is_large_inode && large_inode->i_extra_isize >= 24) {
		fprintf(out, "%sGeneration: %u    Version: 0x%08x:%08x\n",
			prefix, inode->i_generation, large_inode->i_version_hi,
			inode->osd1.linux1.l_i_version);
	} else {
		fprintf(out, "%sGeneration: %u    Version: 0x%08x\n", prefix,
			inode->i_generation, inode->osd1.linux1.l_i_version);
	}
	fprintf(out, "%sUser: %5d   Group: %5d",
		prefix, inode_uid(*inode), inode_gid(*inode));
	if (is_large_inode && large_inode->i_extra_isize >= 32)
		fprintf(out, "   Project: %5d", large_inode->i_projid);
	fputs("   Size: ", out);
	if (LINUX_S_ISREG(inode->i_mode))
		fprintf(out, "%llu\n", EXT2_I_SIZE(inode));
	else
		fprintf(out, "%d\n", inode->i_size);
	if (os == EXT2_OS_HURD)
		fprintf(out,
			"%sFile ACL: %d    Directory ACL: %d Translator: %d\n",
			prefix,
			inode->i_file_acl, LINUX_S_ISDIR(inode->i_mode) ? inode->i_dir_acl : 0,
			inode->osd1.hurd1.h_i_translator);
	else
		fprintf(out, "%sFile ACL: %llu    Directory ACL: %d\n",
			prefix,
			inode->i_file_acl | ((long long)
				(inode->osd2.linux2.l_i_file_acl_high) << 32),
			LINUX_S_ISDIR(inode->i_mode) ? inode->i_dir_acl : 0);
	if (os != EXT2_OS_HURD)
		fprintf(out, "%sLinks: %d   Blockcount: %llu\n",
			prefix, inode->i_links_count,
			(((unsigned long long)
			  inode->osd2.linux2.l_i_blocks_hi << 32)) +
			inode->i_blocks);
	else
		fprintf(out, "%sLinks: %d   Blockcount: %u\n",
			prefix, inode->i_links_count, inode->i_blocks);
	switch (os) {
	    case EXT2_OS_HURD:
		frag = inode->osd2.hurd2.h_i_frag;
		fsize = inode->osd2.hurd2.h_i_fsize;
		break;
	    default:
		frag = fsize = 0;
	}
	fprintf(out, "%sFragment:  Address: %d    Number: %d    Size: %d\n",
		prefix, inode->i_faddr, frag, fsize);
	if (is_large_inode && large_inode->i_extra_isize >= 24) {
		fprintf(out, "%s ctime: 0x%08x:%08x -- %s", prefix,
			inode->i_ctime, large_inode->i_ctime_extra,
			inode_time_to_string(inode->i_ctime,
					     large_inode->i_ctime_extra));
		fprintf(out, "%s atime: 0x%08x:%08x -- %s", prefix,
			inode->i_atime, large_inode->i_atime_extra,
			inode_time_to_string(inode->i_atime,
					     large_inode->i_atime_extra));
		fprintf(out, "%s mtime: 0x%08x:%08x -- %s", prefix,
			inode->i_mtime, large_inode->i_mtime_extra,
			inode_time_to_string(inode->i_mtime,
					     large_inode->i_mtime_extra));
		fprintf(out, "%scrtime: 0x%08x:%08x -- %s", prefix,
			large_inode->i_crtime, large_inode->i_crtime_extra,
			inode_time_to_string(large_inode->i_crtime,
					     large_inode->i_crtime_extra));
		if (inode->i_dtime)
			fprintf(out, "%s dtime: 0x%08x:(%08x) -- %s", prefix,
				large_inode->i_dtime, large_inode->i_ctime_extra,
				inode_time_to_string(inode->i_dtime,
						     large_inode->i_ctime_extra));
	} else {
		fprintf(out, "%sctime: 0x%08x -- %s", prefix, inode->i_ctime,
			time_to_string((__s32) inode->i_ctime));
		fprintf(out, "%satime: 0x%08x -- %s", prefix, inode->i_atime,
			time_to_string((__s32) inode->i_atime));
		fprintf(out, "%smtime: 0x%08x -- %s", prefix, inode->i_mtime,
			time_to_string((__s32) inode->i_mtime));
		if (inode->i_dtime)
			fprintf(out, "%sdtime: 0x%08x -- %s", prefix,
				inode->i_dtime,
				time_to_string((__s32) inode->i_dtime));
	}
	if (EXT2_INODE_SIZE(current_fs->super) > EXT2_GOOD_OLD_INODE_SIZE)
		internal_dump_inode_extra(out, prefix, inode_num,
					  (struct ext2_inode_large *) inode);
	dump_inode_attributes(out, inode_num);

	if (ext2fs_has_feature_metadata_csum(current_fs->super)) {
		__u32 crc = inode->i_checksum_lo;
		if (is_large_inode &&
		    large_inode->i_extra_isize >=
				(offsetof(struct ext2_inode_large,
					  i_checksum_hi) -
				 EXT2_GOOD_OLD_INODE_SIZE))
			crc |= ((__u32)large_inode->i_checksum_hi) << 16;
		fprintf(out, "Inode checksum: 0x%08x\n", crc);
	}

	if (LINUX_S_ISLNK(inode->i_mode) &&
	    ext2fs_inode_data_blocks(current_fs, inode) == 0)
		dump_fast_link(out, inode_num, inode, prefix);
	else if (LINUX_S_ISBLK(inode->i_mode) || LINUX_S_ISCHR(inode->i_mode)) {
		int major, minor;
		const char *devnote;

		if (inode->i_block[0]) {
			major = (inode->i_block[0] >> 8) & 255;
			minor = inode->i_block[0] & 255;
			devnote = "";
		} else {
			major = (inode->i_block[1] & 0xfff00) >> 8;
			minor = ((inode->i_block[1] & 0xff) |
				 ((inode->i_block[1] >> 12) & 0xfff00));
			devnote = "(New-style) ";
		}
		fprintf(out, "%sDevice major/minor number: %02d:%02d (hex %02x:%02x)\n",
			devnote, major, minor, major, minor);
	} else if (do_dump_blocks) {
		if (inode->i_flags & EXT4_EXTENTS_FL)
			dump_extents(out, prefix, inode_num,
				     DUMP_LEAF_EXTENTS|DUMP_NODE_EXTENTS, 0, 0);
		else if (inode->i_flags & EXT4_INLINE_DATA_FL)
			dump_inline_data(out, prefix, inode_num);
		else
			dump_blocks(out, prefix, inode_num);
	}
}

static void dump_inode(ext2_ino_t inode_num, struct ext2_inode *inode)
{
	FILE	*out;

	out = open_pager();
	internal_dump_inode(out, "", inode_num, inode, 1);
	close_pager(out);
}

void do_stat(int argc, char *argv[])
{
	ext2_ino_t	inode;
	struct ext2_inode * inode_buf;

	if (check_fs_open(argv[0]))
		return;

	inode_buf = (struct ext2_inode *)
			malloc(EXT2_INODE_SIZE(current_fs->super));
	if (!inode_buf) {
		fprintf(stderr, "do_stat: can't allocate buffer\n");
		return;
	}

	if (common_inode_args_process(argc, argv, &inode, 0)) {
		free(inode_buf);
		return;
	}

	if (debugfs_read_inode_full(inode, inode_buf, argv[0],
					EXT2_INODE_SIZE(current_fs->super))) {
		free(inode_buf);
		return;
	}

	dump_inode(inode, inode_buf);
	free(inode_buf);
	return;
}


#ifndef READ_ONLY

struct rd_struct {
	ext2_ino_t	parent;
	int		empty;
};


#endif /* READ_ONLY */

void do_show_debugfs_params(int argc EXT2FS_ATTR((unused)),
			    char *argv[] EXT2FS_ATTR((unused)))
{
	if (current_fs)
		printf("Open mode: read-%s\n",
		       current_fs->flags & EXT2_FLAG_RW ? "write" : "only");
	printf("Filesystem in use: %s\n",
	       current_fs ? current_fs->device_name : "--none--");
}


static int source_file(const char *cmd_file, int ss_idx)
{
	FILE		*f;
	char		buf[BUFSIZ];
	char		*cp;
	int		exit_status = 0;
	int		retval;

	if (strcmp(cmd_file, "-") == 0)
		f = stdin;
	else {
		f = fopen(cmd_file, "r");
		if (!f) {
			perror(cmd_file);
			exit(1);
		}
	}
	fflush(stdout);
	fflush(stderr);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
	while (!feof(f)) {
		if (fgets(buf, sizeof(buf), f) == NULL)
			break;
		cp = strchr(buf, '\n');
		if (cp)
			*cp = 0;
		cp = strchr(buf, '\r');
		if (cp)
			*cp = 0;
		printf("checkMD: %s\n", buf);
		retval = ss_execute_line(ss_idx, buf);
		if (retval) {
			ss_perror(ss_idx, retval, buf);
			exit_status++;
		}
	}
	if (f != stdin)
		fclose(f);
	return exit_status;
}

int main(int argc, char **argv)
{
	int		retval;
	const char	*usage = 
		"Usage: %s [-b blocksize] [-m mnt_point] [-s superblock] [-f cmd_file] "
		"[-R request] [-V] ["
#ifndef READ_ONLY
		"[-w] [-z undo_file] "
#endif
		"[-c] device]";
	int		c;
	int		open_flags = EXT2_FLAG_SOFTSUPP_FEATURES | EXT2_FLAG_64BITS;
	char		*request = 0;
	char		*mnt_pt = 0;
	int		exit_status = 0;
	char		*cmd_file = 0;
	blk64_t		superblock = 0;
	blk64_t		blocksize = 0;
	int		catastrophic = 0;
	char		*data_filename = 0;
#ifdef READ_ONLY
	const char	*opt_string = "nicR:f:b:s:Vd:Dm:";
#else
	const char	*opt_string = "niwcR:f:b:s:Vd:Dz:m:";
	char		*undo_file = NULL;
#endif
#ifdef CONFIG_JBD_DEBUG
	char		*jbd_debug;
#endif

	if (debug_prog_name == 0)
#ifdef READ_ONLY
		debug_prog_name = "rcheckMD";
#else
		debug_prog_name = "checkMD";
#endif
	add_error_table(&et_ext2_error_table);
	fprintf (stderr, "%s %s (%s)\n", debug_prog_name,
		 E2FSPROGS_VERSION, E2FSPROGS_DATE);

#ifdef CONFIG_JBD_DEBUG
	jbd_debug = ss_safe_getenv("DEBUGFS_JBD_DEBUG");
	if (jbd_debug) {
		int res = sscanf(jbd_debug, "%d", &journal_enable_debug);

		if (res != 1) {
			fprintf(stderr,
				"DEBUGFS_JBD_DEBUG \"%s\" not an integer\n\n",
				jbd_debug);
			exit(1);
		}
	}
#endif
	while ((c = getopt (argc, argv, opt_string)) != EOF) {
		switch (c) {
		case 'R':
			request = optarg;
			break;
		case 'm':
			mnt_pt = optarg;
			break;
		case 'f':
			cmd_file = optarg;
			break;
		case 'd':
			data_filename = optarg;
			break;
		case 'i':
			open_flags |= EXT2_FLAG_IMAGE_FILE;
			break;
		case 'n':
			open_flags |= EXT2_FLAG_IGNORE_CSUM_ERRORS;
			break;
#ifndef READ_ONLY
		case 'w':
			open_flags |= EXT2_FLAG_RW;
			break;
#endif
		case 'D':
			open_flags |= EXT2_FLAG_DIRECT_IO;
			break;
		case 'b':
			blocksize = parse_ulong(optarg, argv[0],
						"block size", 0);
			break;
		case 's':
			retval = strtoblk(argv[0], optarg,
					  "superblock block number",
					  &superblock);
			if (retval)
				return 1;
			break;
		case 'c':
			catastrophic = 1;
			break;
		case 'V':
			/* Print version number and exit */
			fprintf(stderr, "\tUsing %s\n",
				error_message(EXT2_ET_BASE));
			exit(0);
		case 'z':
			undo_file = optarg;
			break;
		default:
			com_err(argv[0], 0, usage, debug_prog_name);
			return 1;
		}
	}
	if (optind < argc)
		open_filesystem(argv[optind], open_flags,
				superblock, blocksize, catastrophic,
				data_filename, undo_file, mnt_pt);

	sci_idx = ss_create_invocation(debug_prog_name, "0.0", (char *) NULL,
				       &debug_cmds, &retval);
	if (retval) {
		ss_perror(sci_idx, retval, "creating invocation");
		exit(1);
	}
	ss_get_readline(sci_idx);

	(void) ss_add_request_table (sci_idx, &ss_std_requests, 1, &retval);
	if (retval) {
		ss_perror(sci_idx, retval, "adding standard requests");
		exit (1);
	}
	if (extra_cmds)
		ss_add_request_table (sci_idx, extra_cmds, 1, &retval);
	if (retval) {
		ss_perror(sci_idx, retval, "adding extra requests");
		exit (1);
	}
	if (request) {
		retval = 0;
		retval = ss_execute_line(sci_idx, request);
		if (retval) {
			ss_perror(sci_idx, retval, request);
			exit_status++;
		}
	} else if (cmd_file) {
		exit_status = source_file(cmd_file, sci_idx);
	} else {
		ss_listen(sci_idx);
	}

	ss_delete_invocation(sci_idx);

	if (current_fs)
		close_filesystem();

	remove_error_table(&et_ext2_error_table);
	return exit_status;
}
