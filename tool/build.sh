#!/bin/sh

cd tiny-sys-fuzz/
gcc -o tiny-sys-fuzz main.c tiny-sys-fuzz.c -lrt -Wl,-T rodata.ld
gcc -o tiny-sys-fuzz32 main.c tiny-sys-fuzz.c -lrt -m32 -Wl,-T rodata.ld
cd ../

cd kptr-lkm/
make
cd ../
