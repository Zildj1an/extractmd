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

