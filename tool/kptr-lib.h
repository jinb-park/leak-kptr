#ifndef _KPTR_LIB_H
#define _KPTR_LIB_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

#define STACK_DATA_SIZE 130

struct stack_data {
	unsigned long long low_offset;
	unsigned long long high_offset;
	unsigned long long kernel_start;
	unsigned long long kernel_end;
	unsigned long long stack_start;
	unsigned long long stack_end;
	unsigned long long data[STACK_DATA_SIZE];
} __attribute__ ((aligned (8)));

#define CMD_SPRAYING_STACK 0
#define CMD_GET_STACK_DATA 1
#define CMD_GET_KPTR_RANGE 2
#define CMD_FOOTPRINT_STACK 3

#define MAGIC_CODE (0x1122334455667788UL)
#define FOOTPRINT_START (0x0101010101010101UL)
#define ARR_SIZE(arr) ((sizeof(arr) / sizeof(arr[0])))
#define KPTR_ENTRY_ARR_MAX (2048)

enum {
	KPTR_TYPE_KERNEL = 0,
	KPTR_TYPE_KERNEL_STACK = 1,
};

struct tsf_fuzz_entry;
typedef int (*TINY_SYS_FUZZ_FUNC)(struct tsf_fuzz_entry *);

struct kptr_range {
	unsigned long long kernel_start;
	unsigned long long kernel_end;
	unsigned long long kernel_stack_start;
	unsigned long long kernel_stack_end;
};

struct tsf_context {
	int out_fd;
	int align;
	struct kptr_range range;
	unsigned long long stack_offset;
};

struct kptr_entry {
	unsigned char func_name[128];
	unsigned long long offset;
	unsigned long long arg0;
	unsigned long long arg1;
	unsigned long long arg2;
	unsigned long long arg3;
	unsigned long long arg4;
	unsigned long long arg5;
	int type;
	int id;
	int sub_id;
	unsigned long long value;	// If the type is kernel core, we should know the value inside the offset. Why? It's for bypassing KASLR.
};

struct tsf_fuzz_entry {
	int id;
	int sub_id;
	unsigned char func_name[128];
	TINY_SYS_FUZZ_FUNC fuzz_func;
};

static inline long kptr_api_syscall(unsigned int cmd, unsigned long long arg)
{
	return quotactl(cmd, NULL, 0, arg);
}

static inline int kptr_api_spraying_stack(void)
{
	int r;

	r = kptr_api_syscall(CMD_SPRAYING_STACK, 0);
	if (r < 0) {
		printf("[-] CMD_SPRAYING_STACK failed\n");
		return r;
	}
	return 0;
}

static inline int kptr_api_footprint_stack(unsigned long long *stack_offset)
{
	int r;

	r = kptr_api_syscall(CMD_FOOTPRINT_STACK, stack_offset);
	if (r < 0) {
		printf("[-] CMD_FOOTPRINT_STACK failed\n");
		return r;
	}
	return 0;
}

extern char *__progname;
#define KPTR_ALIGN 8
static inline int kptr_api_get_stack(char *out_dir, int syscall)
{
	long r;
	int i;
	unsigned long long offset;
	int type;
	struct stack_data data;
	char cmd[1024] = {0,};
	unsigned long val, ptr;

	r = kptr_api_syscall(CMD_GET_STACK_DATA, &data);
	if (r < 0) {
		printf("[-] CMD_GET_STACK_DATA failed\n");
		return r;
	}

	//for (i=0; i<STACK_DATA_SIZE; i++) {
	for (ptr = (unsigned long)&data.data, i = 0; ptr < (unsigned long)&data.data[STACK_DATA_SIZE]; ptr += KPTR_ALIGN, i++) {
		val = *(unsigned long *)ptr;
		offset = data.low_offset - i * KPTR_ALIGN;
		type = -1;

		if (KPTR_ALIGN == 4 && (ptr % 8) == 0)
			continue;

		if (val >= data.kernel_start && val < data.kernel_end)
			type = KPTR_TYPE_KERNEL;
		else if (val >= data.stack_start && val < data.stack_end)
			type = KPTR_TYPE_KERNEL_STACK;

		if (type == -1)
			continue;

		// syscall,type,offset,value,process name
		snprintf(cmd, 1024, "echo \"%d,%d,%ld,%lx,%s\" >> %s/%ld_%d.csv",
					syscall, type, offset, val,
					__progname,
					out_dir, offset, type);
		system(cmd);
	}

	return 0;
}

static inline unsigned long long kptr_api_get_leak_offset(int leak_size, unsigned long long leak_value, unsigned long long stack_offset)
{
	unsigned long long footprint;

	if (leak_value == 0) {
		printf("leak_value is wrong\n");
		return 0;
	}

	footprint = FOOTPRINT_START >> ((8 - leak_size) * 8);
	footprint = leak_value / footprint;
	return stack_offset + (footprint * 8);
}

#ifdef TINY_SYS_FUZZER
int init_ctx(int align);
void exit_ctx(void);
int do_sys_fuzz(void);
void write_out(void);
#endif

#endif
