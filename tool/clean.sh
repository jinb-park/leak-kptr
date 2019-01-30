#!/bin/sh

cd tiny-sys-fuzz/
rm -f tiny-sys-fuzz tiny-sys-fuzz32 out.csv
cd ../

cd kptr-lkm/
make clean
cd ../