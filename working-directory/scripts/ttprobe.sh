#script to apply ttprobe patch to kernel. To be executed in TEACUP/tools/

#!/bin/bash

tar xzvf ttprobe-0.1.tar.gz
cd ttprobe-0.1.2
apt-get update
apt-get install make gcc linuxheaders-$(uname-r)
make
mkdir -p /lib/modules/$(uname -r)/extra
cp -r ttprobe.ko /lib/modules/$(uname -r)/extra/
depmod $(uname -r)