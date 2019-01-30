#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import os
import sys

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "USAGE : python get_coverage.py <out file>"
        sys.exit(0)

    start_offset = 224
    end_offset = 224 + (130 * 8)
    total_entry = (end_offset - start_offset) / 8
    kernel_code_set = set()
    kernel_stack_set = set()
    total_set = set()

    with open(sys.argv[1]) as f:
        lines = f.readlines()
        for num, line in enumerate(lines):
            token = line.split(',')
            ptr_type = int(token[1])
            offset = int(token[4])
            if ptr_type == 0:
                kernel_code_set.add(offset)
            else:
                kernel_stack_set.add(offset)
            total_set.add(offset)

    kernel_code_coverage = (len(kernel_code_set) / float(total_entry)) * 100
    kernel_stack_coverage = (len(kernel_stack_set) / float(total_entry)) * 100
    total_set_coverage = (len(total_set) / float(total_entry)) * 100

    print 'kernel_code_coverage : ' + str(kernel_code_coverage)
    print 'kernel_stack_coverage : ' + str(kernel_stack_coverage)
    print 'total_set_coverage : ' + str(total_set_coverage)
