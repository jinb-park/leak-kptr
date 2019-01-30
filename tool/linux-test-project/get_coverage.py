#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import os
import sys
from os import walk

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "USAGE : sudo python get_coverage.py <out dir>"
        sys.exit(0)

    start_offset = 224
    end_offset = 224 + (130 * 8)
    total_entry = (end_offset - start_offset) / 8
    kernel_code_set = set()
    kernel_stack_set = set()
    total_set = set()

    for (dirpath, dirnames, filenames) in walk(sys.argv[1]):
        for f in filenames:
            token = f.split('_')
            if token[1] == '0.csv':
                kernel_code_set.add(int(token[0]))
            else:
                kernel_stack_set.add(int(token[0]))
            total_set.add(int(token[0]))

    kernel_code_coverage = (len(kernel_code_set) / float(total_entry)) * 100
    kernel_stack_coverage = (len(kernel_stack_set) / float(total_entry)) * 100
    total_set_coverage = (len(total_set) / float(total_entry)) * 100

    print 'kernel_code_coverage : ' + str(kernel_code_coverage)
    print 'kernel_stack_coverage : ' + str(kernel_stack_coverage)
    print 'total_set_coverage : ' + str(total_set_coverage)
