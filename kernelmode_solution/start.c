#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <linux/fs.h>

#include "extractmd.h"

int main(int argc, char *argv[])
{
	int fd = open("/dev/extractmd", O_RDWR);

	struct extractmd_path p;
	char dir_sb[255] = {0};
	char dir_bd[255] = {0};
	char dir_journal[255] = {0};

	if (argc != 5)
	{	
		printf("usage : ./start [device] [mount point] [path-you-want] [realtime 0 or 1] (e.q., #./start /dev/sdb /mnt ./md 0)\n");
		return 0;
	}

	sprintf(dir_sb, "%s/sb", argv[3]);
	sprintf(dir_bd, "%s/bd", argv[3]);
	sprintf(dir_journal, "%s/journal", argv[3]);

	mkdir(argv[3], 0777);
	mkdir(dir_sb, 0777);
	mkdir(dir_bd, 0777);
	mkdir(dir_journal, 0777);

	p.path_device = argv[1];      // Device
	p.path_mount_point = argv[2]; // Mount point
	p.path = argv[3];              // Where to store files of metadata
	p.realtime = atoi(argv[4]);

	ioctl(fd,&p);                 // Syscall

 	close(fd);

	return 0;
}
