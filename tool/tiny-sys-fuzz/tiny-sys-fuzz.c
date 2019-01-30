#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sched.h>
#include <limits.h>
#include <syscall.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/uio.h>
//#include <sys/capability.h>
#include <sys/quota.h>
#include <mqueue.h>
#include <linux/random.h>
#include <linux/membarrier.h>
#include "../kptr-lib.h"

extern const void *const rodata_start;
extern const void *const rodata_end;

static struct tsf_context ctx;
static struct kptr_entry kptr_entry_arr[KPTR_ENTRY_ARR_MAX];
static int kptr_entry_arr_idx = 0;

void add_kptr_entry(struct tsf_fuzz_entry *entry, unsigned long long offset, 
					unsigned long long arg0, unsigned long long arg1, unsigned long long arg2,
					unsigned long long arg3, unsigned long long arg4, unsigned long long arg5,
					int type, unsigned long long value)
{
	int idx = kptr_entry_arr_idx;
	int i;

	// filtering duplicated one
	/*
	for (i=0; i<idx; i++) {
		if (kptr_entry_arr[i].offset == offset &&
			kptr_entry_arr[i].type == type)
			return;
	}
	*/

	strcpy(kptr_entry_arr[idx].func_name, entry->func_name);
	kptr_entry_arr[idx].offset = offset;
	kptr_entry_arr[idx].arg0 = arg0;
	kptr_entry_arr[idx].arg1 = arg1;
	kptr_entry_arr[idx].arg2 = arg2;
	kptr_entry_arr[idx].arg3 = arg3;
	kptr_entry_arr[idx].arg4 = arg4;
	kptr_entry_arr[idx].arg5 = arg5;
	kptr_entry_arr[idx].type = type;
	kptr_entry_arr[idx].value = value;
	kptr_entry_arr[idx].id = entry->id;
	kptr_entry_arr[idx].sub_id = entry->sub_id;
	kptr_entry_arr_idx++;
}

long tsf_syscall(unsigned int cmd, unsigned long long arg)
{
	return quotactl(cmd, NULL, 0, arg);
}

// leak_size must be one of 1, 2, 4, 8.
unsigned long long tsf_get_leak_offset(int leak_size, unsigned long long leak_value)
{
	unsigned long long footprint;

	if (leak_value == 0) {
		printf("leak_value is wrong\n");
		return 0;
	}

	footprint = FOOTPRINT_START >> (leak_size * 8);
	footprint = leak_value / footprint;
	footprint--;
	return ctx.stack_offset + (footprint * 8);
}

int tsf_footprint_stack(void)
{
	long r;

	r = tsf_syscall(CMD_FOOTPRINT_STACK, &ctx.stack_offset);
	if (r < 0) {
		printf("[-] CMD_FOOTPRINT_STACK failed\n");
		return r;
	}

	return 0;
}

int tsf_spraying_stack(void)
{
	long r;

	r = tsf_syscall(CMD_SPRAYING_STACK, 0);
	if (r < 0) {
		printf("[-] CMD_SPRAYING_STACK failed\n");
		return r;
	}

	return 0;
}

int tsf_get_stack(struct tsf_fuzz_entry *entry, unsigned long long arg0, unsigned long long arg1, unsigned long long arg2,
					unsigned long long arg3, unsigned long long arg4, unsigned long long arg5)
{
	long r;
	int i;
	struct stack_data data;
	int idx = kptr_entry_arr_idx;
	unsigned long long val, ptr;

	if (idx >= KPTR_ENTRY_ARR_MAX) {
		printf("kptr entry array is full\n");
		return -1;
	}

	r = tsf_syscall(CMD_GET_STACK_DATA, &data);
	if (r < 0) {
		printf("[-] CMD_GET_STACK_DATA failed\n");
		return r;
	}

	for (ptr = (unsigned long long)&data.data, i = 0; ptr < (unsigned long long)&data.data[STACK_DATA_SIZE]; ptr += ctx.align, i++) {
		val = *(unsigned long long *)ptr;

		if (ctx.align == 4 && ptr % 8 == 0) {
			continue;
		}

		if (val >= ctx.range.kernel_start && val < ctx.range.kernel_end) {
			add_kptr_entry(entry, data.low_offset - (i * ctx.align),
							arg0, arg1, arg2, arg3, arg4, arg5,
							KPTR_TYPE_KERNEL, val);
		}
		else if (val >= ctx.range.kernel_stack_start && val < ctx.range.kernel_stack_end) {
			add_kptr_entry(entry, data.low_offset - (i * ctx.align),
							arg0, arg1, arg2, arg3, arg4, arg5,
							KPTR_TYPE_KERNEL_STACK, val);
		}
	}

	return 0;
}

int tsf_get_kptr_range(struct kptr_range *range)
{
	long r;

	r = tsf_syscall(CMD_GET_KPTR_RANGE, range);
	if (r < 0) {
		printf("[-] CMD_GET_KPTR_RANGE failed\n");
		return r;
	}

	return 0;
}

/*
 * functions for syscall fuzzing - start
 */
int tsf_fuzz_mmap(struct tsf_fuzz_entry *entry)
{
	char *data;

	entry->sub_id = 0;
	tsf_spraying_stack();
	data = mmap(NULL, 0xa000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	tsf_get_stack(entry, NULL, 0xa000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	munmap(data, 0xa000);

	entry->sub_id = 1;
	tsf_spraying_stack();
	data = mmap(NULL, 0xa000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	tsf_get_stack(entry, NULL, 0xa000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED, -1, 0);
	munmap(data, 0xa000);

	entry->sub_id = 2;
	tsf_spraying_stack();
	data = mmap(NULL, 0xa000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	tsf_get_stack(entry, NULL, 0xa000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
	munmap(data, 0xa000);

	return 0;
}
int tsf_fuzz_madvise(struct tsf_fuzz_entry *entry)
{
	char *data;
	int sub_id;

	data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	for (sub_id = MADV_NORMAL; sub_id <= MADV_DODUMP; sub_id++) {
		entry->sub_id = sub_id;
		tsf_spraying_stack();
		madvise(data, 0x1000, MADV_WILLNEED);
		tsf_get_stack(entry, (unsigned long)data, 0x1000, sub_id, 0, 0, 0);
	}

	munmap(data, 0x1000);
	return 0;
}
int tsf_fuzz_socket(struct tsf_fuzz_entry *entry)
{
	int sock;

	entry->sub_id = 0;
	tsf_spraying_stack();
	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	tsf_get_stack(entry, AF_UNIX, SOCK_DGRAM, 0, 0, 0, 0);
	close(sock);

	entry->sub_id = 1;
	tsf_spraying_stack();
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	tsf_get_stack(entry, AF_UNIX, SOCK_STREAM, 0, 0, 0, 0);
	close(sock);

	entry->sub_id = 2;
	tsf_spraying_stack();
	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	tsf_get_stack(entry, AF_UNIX, SOCK_SEQPACKET, 0, 0, 0, 0);
	close(sock);

	entry->sub_id = 3;
	tsf_spraying_stack();
	sock = socket(AF_INET, SOCK_DGRAM, 0);
	tsf_get_stack(entry, AF_INET, SOCK_DGRAM, 0, 0, 0, 0);
	close(sock);

	entry->sub_id = 4;
	tsf_spraying_stack();
	sock = socket(AF_INET, SOCK_STREAM, 0);
	tsf_get_stack(entry, AF_INET, SOCK_STREAM, 0, 0, 0, 0);
	close(sock);

	return 0;
}
int tsf_fuzz_write(struct tsf_fuzz_entry *entry)
{
	int sock, fd;
	sock = socket(AF_UNIX, SOCK_DGRAM, 0);

	entry->sub_id = 0;
	tsf_spraying_stack();
	write(sock, "hello", sizeof("hello"));
	tsf_get_stack(entry, sock, "hello", sizeof("hello"), 0, 0, 0);
	close(sock);

	entry->sub_id = 1;
	fd = open("./tmp.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	tsf_spraying_stack();
	write(fd, "hello", sizeof("hello"));
	tsf_get_stack(entry, fd, "hello", sizeof("hello"), 0, 0, 0);
	close(fd);
	unlink("./tmp.txt");

	return 0;
}
int tsf_fuzz_adjtimex(struct tsf_fuzz_entry *entry)
{
	struct timex time;

	memset(&time, 0, sizeof(time));
	entry->sub_id = 0;
	tsf_spraying_stack();
	adjtimex(&time);
	tsf_get_stack(entry, &time, 0, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_sleep(struct tsf_fuzz_entry *entry)
{
	entry->sub_id = 0;
	tsf_spraying_stack();
	sleep(0);
	tsf_get_stack(entry, 0, 0, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_munmap(struct tsf_fuzz_entry *entry)
{
	char *data;

	data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	entry->sub_id = 0;
	tsf_spraying_stack();
	munmap(data, 0x1000);
	tsf_get_stack(entry, data, 0x1000, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_shm_open(struct tsf_fuzz_entry *entry)
{
	int fd;
	entry->sub_id = 0;
	tsf_spraying_stack();
	fd = shm_open("tsf_fuzz", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	tsf_get_stack(entry, "tsf_fuzz", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 0, 0, 0);
	close(fd);
	shm_unlink("tsf_fuzz");
	return 0;
}
int tsf_fuzz_shm_unlink(struct tsf_fuzz_entry *entry)
{
	int fd;
	entry->sub_id = 0;
	fd = shm_open("tsf_fuzz", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	close(fd);
	tsf_spraying_stack();
	shm_unlink("tsf_fuzz");
	tsf_get_stack(entry, "tsf_fuzz", 0, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_mq_open(struct tsf_fuzz_entry *entry)
{
	mqd_t id;

	entry->sub_id = 0;
	tsf_spraying_stack();
	id = mq_open("tsf_fuzz", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, NULL);
	tsf_get_stack(entry, "tsf_fuzz", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, 0, 0, 0);
	mq_close(id);
	mq_unlink("tsf_fuzz");
	return 0;
}
int tsf_fuzz_gettimeofday(struct tsf_fuzz_entry *entry)
{
	struct timeval tv;
	struct timezone tz;

	entry->sub_id = 0;
	tsf_spraying_stack();
	gettimeofday(&tv, &tz);
	tsf_get_stack(entry, &tv, &tz, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_settimeofday(struct tsf_fuzz_entry *entry)
{
	struct timeval tv;
	struct timezone tz;

	entry->sub_id = 0;
	tsf_spraying_stack();
	settimeofday(&tv, &tz);
	tsf_get_stack(entry, &tv, &tz, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_getpriority(struct tsf_fuzz_entry *entry)
{
	entry->sub_id = 0;
	tsf_spraying_stack();
	getpriority(PRIO_PROCESS, 0);
	tsf_get_stack(entry, PRIO_PROCESS, 0, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_sendmsg(struct tsf_fuzz_entry *entry)
{
	int sock;
	struct msghdr msg;
	struct iovec iov;
	char buf[128];

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	iov.iov_base = buf;
	iov.iov_len = 128;
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	entry->sub_id = 0;
	tsf_spraying_stack();
	sendmsg(sock, &msg, 0);
	tsf_get_stack(entry, sock, &msg, 0, 0, 0, 0);

	close(sock);
	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	entry->sub_id = 1;
	tsf_spraying_stack();
	sendmsg(sock, &msg, 0);
	tsf_get_stack(entry, sock, &msg, 0, 0, 0, 0);

	close(sock);
	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	entry->sub_id = 2;
	tsf_spraying_stack();
	sendmsg(sock, &msg, 0);
	tsf_get_stack(entry, sock, &msg, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_pipe(struct tsf_fuzz_entry *entry)
{
	int pipefds[2];

	entry->sub_id = 0;
	tsf_spraying_stack();
	pipe(pipefds);
	tsf_get_stack(entry, pipefds, 0, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_access(struct tsf_fuzz_entry *entry)
{
	entry->sub_id = 0;
	tsf_spraying_stack();
	access("/proc/iomem", R_OK);
	tsf_get_stack(entry, "/proc/iomem", R_OK, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_getpid(struct tsf_fuzz_entry *entry)
{
	entry->sub_id = 0;
	tsf_spraying_stack();
	getpid();
	tsf_get_stack(entry, 0, 0, 0, 0, 0, 0);

	entry->sub_id = 1;
	tsf_spraying_stack();
	getppid();
	tsf_get_stack(entry, 0, 0, 0, 0, 0, 0);

	entry->sub_id = 2;
	tsf_spraying_stack();
	getuid();
	tsf_get_stack(entry, 0, 0, 0, 0, 0, 0);

	entry->sub_id = 3;
	tsf_spraying_stack();
	getgid();
	tsf_get_stack(entry, 0, 0, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_membarrier(struct tsf_fuzz_entry *entry)
{
	entry->sub_id = 0;
	tsf_spraying_stack();
	syscall(__NR_membarrier, MEMBARRIER_CMD_QUERY, 0);
	tsf_get_stack(entry, MEMBARRIER_CMD_QUERY, 0, 0, 0, 0, 0);
	return 0;
}
/*
int tsf_fuzz_capget(struct tsf_fuzz_entry *entry)
{
	struct __user_cap_header_struct ht;
	struct __user_cap_data_struct dt;

	entry->sub_id = 0;
	tsf_spraying_stack();
	capget(&ht, &dt);
	tsf_get_stack(entry, &ht, &dt, 0, 0, 0, 0);
	return 0;
}*/
int tsf_fuzz_open(struct tsf_fuzz_entry *entry)
{
	int fd;

	entry->sub_id = 0;
	tsf_spraying_stack();
	fd = open("/proc/iomem", O_RDONLY);
	tsf_get_stack(entry, "/proc/iomem", O_RDONLY, 0, 0, 0, 0);

	entry->sub_id = 1;
	tsf_spraying_stack();
	fd = open("/proc/jbjbjb", O_RDONLY);
	tsf_get_stack(entry, "/proc/jbjbjb", O_RDONLY, 0, 0, 0, 0);
	return 0;
}
int tsf_fuzz_mprotect(struct tsf_fuzz_entry *entry)
{
	char *data;

	data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	entry->sub_id = 0;
	tsf_spraying_stack();
	mprotect(data, 0x1000, PROT_READ | PROT_EXEC);
	tsf_get_stack(entry, data, 0x1000, PROT_READ | PROT_EXEC, 0, 0, 0);

	entry->sub_id = 1;
	tsf_spraying_stack();
	mprotect(data, 0x1000, PROT_READ);
	tsf_get_stack(entry, data, 0x1000, PROT_READ, 0, 0, 0);

	entry->sub_id = 2;
	tsf_spraying_stack();
	mprotect(data, 0x1000, PROT_NONE);
	tsf_get_stack(entry, data, 0x1000, PROT_NONE, 0, 0, 0);

	munmap(data, 0x1000);
	return 0;
}
int tsf_fuzz_msync(struct tsf_fuzz_entry *entry)
{
	char *data;

	data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	entry->sub_id = 0;
	tsf_spraying_stack();
	msync(data, 0x1000, MS_INVALIDATE);
	tsf_get_stack(entry, data, 0x1000, MS_INVALIDATE, 0, 0, 0);

	munmap(data, 0x1000);
	return 0;
}
int tsf_fuzz_mremap(struct tsf_fuzz_entry *entry)
{
	char *data;

	data = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	entry->sub_id = 0;
	tsf_spraying_stack();
	mremap(data, 0x1000, 0x1000, MREMAP_MAYMOVE);
	tsf_get_stack(entry, (unsigned long)data, 0x1000, 0x1000, MREMAP_MAYMOVE, 0, 0);

	return 0;
}
int tsf_fuzz_semctl(struct tsf_fuzz_entry *entry)
{
	int semid;
	union semun{
      int                  val;
      struct   semid_ds   *buf;
      unsigned short int  *arrary;
    }  arg;
	semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
	arg.val = 1;

	entry->sub_id = 0;
	tsf_spraying_stack();
	semctl(semid, 0, SETVAL, arg);
	tsf_get_stack(entry, semid, 0, SETVAL, (unsigned long)&arg, 0, 0);

	semctl(semid, 0, IPC_RMID, arg);
	return 0;
}
int tsf_fuzz_random_fuzz(struct tsf_fuzz_entry *entry)
{
	unsigned long sub_id;
	int random = 8, i;
	unsigned long arg0, arg1, arg2, arg3, arg4, arg5;

#ifdef RANDOM_FUZZ
	for (sub_id = 0; sub_id < 326; sub_id++) {
		if (sub_id == __NR_rt_sigreturn || sub_id == __NR_pause || sub_id == __NR_clone || sub_id == __NR_fork ||
			sub_id == __NR_quotactl || sub_id == __NR_clock_nanosleep || sub_id == __NR_exit_group ||
			sub_id == __NR_select || sub_id == __NR_pselect6 || sub_id == __NR_ppoll || sub_id == __NR_seccomp)
			continue;

		for (i=0; i<random; i++) {
			arg0 = arg1 = arg2 = arg3 = arg4 = arg5 = (i * 8);
/*
			arg0 = rand() % 16;
			arg1 = rand() % 16;
			arg2 = rand() % 16;
			arg3 = rand() % 16;
			arg4 = rand() % 16;
			arg5 = rand() % 16;*/

			/*
			syscall(__NR_getrandom, &arg0, sizeof(unsigned long), 0);
			syscall(__NR_getrandom, &arg1, sizeof(unsigned long), 0);
			syscall(__NR_getrandom, &arg2, sizeof(unsigned long), 0);
			syscall(__NR_getrandom, &arg3, sizeof(unsigned long), 0);
			syscall(__NR_getrandom, &arg4, sizeof(unsigned long), 0);
			syscall(__NR_getrandom, &arg5, sizeof(unsigned long), 0);*/

			entry->sub_id = (int)sub_id;
			tsf_spraying_stack();
			asm volatile(
			"pushq %%rax\n"
			"pushq %%rdi\n"
			"pushq %%rsi\n"
			"pushq %%rdx\n"
			"pushq %%r10\n"
			"pushq %%r8\n"
			"pushq %%r9\n"
			"movq %0, %%rax\n\t"
			"movq %1, %%rdi\n\t"
			"movq %2, %%rsi\n\t"
			"movq %3, %%rdx\n\t"
			"movq %4, %%r10\n\t"
			"movq %5, %%r8\n\t"
			"movq %6, %%r9\n\t"
			"syscall\n"
			"popq %%r9\n"
			"popq %%r8\n"
			"popq %%r10\n"
			"popq %%rdx\n"
			"popq %%rsi\n"
			"popq %%rdi\n"
			"popq %%rax\n"
			: /* No output */
			: "r"(sub_id), "r"(arg0), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5)
			: "memory", "rax", "rdx", "rsi", "rdi", "r8", "r9", "r10");
			tsf_get_stack(entry, arg0, arg1, arg2, arg3, arg4, arg5);
		}
	}
#endif
	return 0;
}
/*
 * functions for syscall fuzzing - end
 */
struct tsf_fuzz_entry tsf_fuzz_arr[] = {
	{ .id = 0, .sub_id = 0, .func_name = "mmap", .fuzz_func = tsf_fuzz_mmap },
	{ .id = 1, .sub_id = 0, .func_name = "madvise", .fuzz_func = tsf_fuzz_madvise },
	{ .id = 2, .sub_id = 0, .func_name = "socket", .fuzz_func = tsf_fuzz_socket },
	{ .id = 3, .sub_id = 0, .func_name = "write", .fuzz_func = tsf_fuzz_write },
	{ .id = 4, .sub_id = 0, .func_name = "adjtimex", .fuzz_func = tsf_fuzz_adjtimex },
	{ .id = 5, .sub_id = 0, .func_name = "sleep", .fuzz_func = tsf_fuzz_sleep },
	{ .id = 6, .sub_id = 0, .func_name = "munmap", .fuzz_func = tsf_fuzz_munmap },
	{ .id = 7, .sub_id = 0, .func_name = "shm_open", .fuzz_func = tsf_fuzz_shm_open },
	{ .id = 8, .sub_id = 0, .func_name = "shm_unlink", .fuzz_func = tsf_fuzz_shm_unlink },
	{ .id = 9, .sub_id = 0, .func_name = "mq_open", .fuzz_func = tsf_fuzz_mq_open },
	{ .id = 10, .sub_id = 0, .func_name = "gettimeofday", .fuzz_func = tsf_fuzz_gettimeofday },
	{ .id = 11, .sub_id = 0, .func_name = "settimeofday", .fuzz_func = tsf_fuzz_settimeofday },
	{ .id = 12, .sub_id = 0, .func_name = "getpriority", .fuzz_func = tsf_fuzz_getpriority },
	{ .id = 13, .sub_id = 0, .func_name = "sendmsg", .fuzz_func = tsf_fuzz_sendmsg },
	{ .id = 14, .sub_id = 0, .func_name = "pipe", .fuzz_func = tsf_fuzz_pipe },
	{ .id = 15, .sub_id = 0, .func_name = "access", .fuzz_func = tsf_fuzz_access },
	{ .id = 16, .sub_id = 0, .func_name = "getpid", .fuzz_func = tsf_fuzz_getpid },
	{ .id = 17, .sub_id = 0, .func_name = "membarrier", .fuzz_func = tsf_fuzz_membarrier },
	//{ .id = 18, .sub_id = 0, .func_name = "capget", .fuzz_func = tsf_fuzz_capget },
	{ .id = 19, .sub_id = 0, .func_name = "open", .fuzz_func = tsf_fuzz_open },
	{ .id = 20, .sub_id = 0, .func_name = "mprotect", .fuzz_func = tsf_fuzz_mprotect },
	{ .id = 21, .sub_id = 0, .func_name = "msync", .fuzz_func = tsf_fuzz_msync },
	{ .id = 22, .sub_id = 0, .func_name = "mremap", .fuzz_func = tsf_fuzz_mremap },
	{ .id = 23, .sub_id = 0, .func_name = "semctl", .fuzz_func = tsf_fuzz_semctl },
//
//	last is random-fuzzing
	{ .id = 999, .sub_id = 0, .func_name = "random_fuzz", .fuzz_func = tsf_fuzz_random_fuzz },
};

int do_sys_fuzz(void)
{
	int i, r;

	printf("[] syacall fuzzing start\n");
	for (i=0; i<ARR_SIZE(tsf_fuzz_arr); i++) {
		r = tsf_fuzz_arr[i].fuzz_func(&tsf_fuzz_arr[i]);
		if (r)
			return -1;
	}
	printf("[] syacall fuzzing end\n"); 

	return 0;
}

int is_rodata(unsigned long long addr)
{
	if (addr >= (unsigned long long)&rodata_start &&
		addr < (unsigned long long)&rodata_end)
		return 1;
	return 0;
}

#define BUILD_FORMAT_BUF_ARG(arg) \
	if (is_rodata(entry->arg)) \
		strcat(format_buf, "%s,"); \
	else \
		strcat(format_buf, "%llx,");

void build_format_buf(struct kptr_entry *entry, char *format_buf)
{
	BUILD_FORMAT_BUF_ARG(arg0);
	BUILD_FORMAT_BUF_ARG(arg1);
	BUILD_FORMAT_BUF_ARG(arg2);
	BUILD_FORMAT_BUF_ARG(arg3);
	BUILD_FORMAT_BUF_ARG(arg4);
	BUILD_FORMAT_BUF_ARG(arg5);
	strcat(format_buf,"\n");
}

void write_out(void)
{
	int i;
	char buf[2048] = {0,};
	char format_buf[1024] = {0,};

	for (i=0; i<kptr_entry_arr_idx; i++) {	
		// func_name, type, id, sub_id, offset, value, arg0, arg1, arg2, arg3, arg4, arg5
		//sprintf(buf, "%s,%d,%d,%d,%ld,%lx,%lx,%lx,%lx,%lx,%lx,%lx\n",

		// set format buffer
		strcpy(format_buf, "%s,%d,%d,%d,%lld,%llx,");
		build_format_buf(&kptr_entry_arr[i], format_buf);

		//sprintf(buf, "%s,%d,%d,%d,%lld,%llx,%llx,%llx,%llx,%llx,%llx,%llx\n",
		sprintf(buf, format_buf,
					kptr_entry_arr[i].func_name, kptr_entry_arr[i].type, kptr_entry_arr[i].id, kptr_entry_arr[i].sub_id,
					kptr_entry_arr[i].offset, kptr_entry_arr[i].value,
					kptr_entry_arr[i].arg0, kptr_entry_arr[i].arg1, kptr_entry_arr[i].arg2,
					kptr_entry_arr[i].arg3, kptr_entry_arr[i].arg4, kptr_entry_arr[i].arg5);
		write(ctx.out_fd, buf, strlen(buf));
	}
	printf("[] write result to out.csv. total entries : %d\n", kptr_entry_arr_idx);
}

int init_ctx(int align)
{
	int r;

	ctx.out_fd = open("./out.csv", O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (ctx.out_fd < 0) {
		printf("open error\n");
		return -1;
	}

	r = tsf_get_kptr_range(&ctx.range);
	if (r)
		return -1;

	ctx.align = align;
	printf("[] init_ctx success\n");
	return 0;
}

void exit_ctx(void)
{
	close(ctx.out_fd);
	printf("[] exit_ctx success\n");
}
