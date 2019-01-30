#define _GNU_SOURCE
#define TINY_SYS_FUZZER
#include "../kptr-lib.h"
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>

int main(int argc, char **argv)
{
	int r;
	int align = 8;

	if (argc == 2) {
		// argv[1] is align
		align = atoi(argv[1]);
	}

	r = init_ctx(align);
	if (r)
		return r;

	do_sys_fuzz();
	write_out();

	exit_ctx();
	return 0;
}
