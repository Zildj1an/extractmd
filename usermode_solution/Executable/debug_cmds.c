/* ../../debugfs/debug_cmds.c - automatically generated from ../../debugfs/debug_cmds.ct */
#include <ss/ss.h>

static char const * const ssu00001[] = {
"show_debugfs_params",
    "params",
    (char const *)0
};
extern void do_show_debugfs_params __SS_PROTO;
static char const * const ssu00002[] = {
"open_filesys",
    "open",
    (char const *)0
};
extern void do_open_filesys __SS_PROTO;
static char const * const ssu00003[] = {
"close_filesys",
    "close",
    (char const *)0
};
extern void do_close_filesys __SS_PROTO;
static char const * const ssu00004[] = {
"analyze_meta_data",
    "features",
    (char const *)0
};
extern void do_analyze_meta_data __SS_PROTO;
static char const * const ssu00005[] = {
"extract_meta_data",
    "features",
    (char const *)0
};
extern void do_extract_meta_data __SS_PROTO;
static char const * const ssu00006[] = {
"show_super_stats",
    "stats",
    (char const *)0
};
extern void do_show_super_stats __SS_PROTO;
static char const * const ssu00007[] = {
"show_inode_info",
    "stat",
    (char const *)0
};
extern void do_stat __SS_PROTO;
static ss_request_entry ssu00008[] = {
    { ssu00001,
      do_show_debugfs_params,
      "Show debugfs parameters",
      0 },
    { ssu00002,
      do_open_filesys,
      "Open a filesystem",
      0 },
    { ssu00003,
      do_close_filesys,
      "Close the filesystem",
      0 },
    { ssu00004,
      do_analyze_meta_data,
      "Analyze all meta data",
      0 },
    { ssu00005,
      do_extract_meta_data,
      "Extract all meta data",
      0 },
    { ssu00006,
      do_show_super_stats,
      "Show superblock statistics",
      0 },
    { ssu00007,
      do_stat,
      "Show inode information ",
      0 },
    { 0, 0, 0, 0 }
};

ss_request_table debug_cmds = { 2, ssu00008 };
