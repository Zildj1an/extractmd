Kernel module tutorial

1. Compile : compile the module on your machine.
#make


2. Load module 
#insmod extractmd.ko


3. Start extraction
#./start [device] [mount point] [path-to-store-files] [realtime 0 or 1]
For example : #./start /dev/sdb /mnt ./md 0
This will extract metadata of target device and store files on ./md


4. If you want to remove module
#rmmod extractmd

=======================================================================================================================
11/27/2016 v4.0
Now can extract reserved GDT, journal

How to use?
#make                // compile the module
#insmod extractmd.ko // load the module
#./a.out             // trigger extraction
#rmmod extractmd     // this will unload the module
Look test.c and specify target device, and the path where to store files.
For journal, the module append data on a file. So, never mind journal.

11/25/2016 v3.0
Specify path : 1.mount point(e.q., "/mnt"), 2.target device(e.q., "/dev/sdb"), 3.where to store extracted meta data(e.q., "/home/user/md").
Example code : test.c

11/15/2016 v2.0
You can now extract inode of specific file.
To extract inode, you should specify path of file(e.q., "/mnt/testF")
Look test.c

11/11/2016 v1.1
in extractmd.h
struct extractmd_meta_data contains extractmd_super_block and extractmd_group_desc.
in extractmd.c
Now, extractmd module will extract extractmd_meta_data(containing super_block and group_desc).

See test.c to know how to use.

11/11/2016 v1.0

in extractmd.h
ext4_super_group -> extractmd_super_group
ext4_group_desc  -> extractmd_group_desc

Prerequisite
1. The target device should be mounted on /mnt with ext4 filesystem

How to use?
1. in your command line
insert extractmd kernel module.(needs root permit)
~#insmod extractmd.ko

2. Then, you should make a test code.
"test.c" is an example.

/* Open */
int fd = open("/dev/extractmd", O_RDWR);

/* super_block in user space */
struct extractmd_super_block super_block;

/* ioctl will copy super_block from kernel space */
inctl(fd, &super_block);

/* Now super_block is copied
 * ...do sometiing here with super_block...
 */

/* Close */
close(fd);
