#!/bin/sh

sudo cp -f kptr-lib.h /usr/include/
sudo insmod kptr-lkm/kptr-lkm.ko
