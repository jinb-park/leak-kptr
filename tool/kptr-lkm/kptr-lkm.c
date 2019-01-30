#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/msg.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <asm/syscall.h>
#include <asm/tlbflush.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/kallsyms.h>
#include <linux/livepatch.h>
#include <linux/version.h>

#define STACK_DATA_SIZE 130

struct poc_lkm_size {
	char dummy[128];
};

struct stack_data {
	unsigned long low_offset;
	unsigned long high_offset;
	unsigned long kernel_start;
	unsigned long kernel_end;
	unsigned long stack_start;
	unsigned long stack_end;
	unsigned long data[STACK_DATA_SIZE];
};

struct kptr_range {
	unsigned long kernel_start;
	unsigned long kernel_end;
	unsigned long kernel_stack_start;
	unsigned long kernel_stack_end;
};

#define CMD_SPRAYING_STACK 0
#define CMD_GET_STACK_DATA 1
#define CMD_GET_KPTR_RANGE 2
#define CMD_FOOTPRINT_STACK 3

#define MAGIC_CODE (0x1122334455667788UL)
#define FOOTPRINT_START (0x0101010101010101UL)
#define ARR_SIZE(arr) ((sizeof(arr) / sizeof(arr[0])))

static unsigned long kptr_kernel_start = 0;
static unsigned long kptr_kernel_end = 0;

int kptr_get_kptr_range(unsigned long arg)
{
	struct kptr_range range;

	range.kernel_start = (unsigned long)kallsyms_lookup_name("_stext");
	range.kernel_end = (unsigned long)kallsyms_lookup_name("_etext");
	range.kernel_stack_start = (unsigned long)current->stack;
	range.kernel_stack_end = (unsigned long)current->stack + THREAD_SIZE;

	if (copy_to_user((void *)arg, &range, sizeof(range))) {
		pr_info("copy_to_user error\n");
		return -1;
	}
	return 0;
}

// Arguments that tsf uses are cmd, arg.
long kptr_syscall(unsigned int cmd, const char *special, int id, unsigned long arg)
{
	struct stack_data obj;

	if (cmd == CMD_SPRAYING_STACK) {
		int i;
		for (i=0; i<STACK_DATA_SIZE; i++)
			obj.data[i] = MAGIC_CODE;
	}
	else if (cmd == CMD_GET_STACK_DATA) {
		obj.low_offset = ((unsigned long)current->stack + THREAD_SIZE) - (unsigned long)&obj.data;
		obj.high_offset = ((unsigned long)current->stack + THREAD_SIZE) - ((unsigned long)&obj.data + sizeof(obj.data));
		obj.stack_start = (unsigned long)current->stack;
		obj.stack_end = ((unsigned long)current->stack + THREAD_SIZE);
		obj.kernel_start = kptr_kernel_start;
		obj.kernel_end = kptr_kernel_end;

		if (copy_to_user((void *)arg, &obj, sizeof(obj))) {
			pr_info("copy_to_user error\n");
			return -1;
		}
	}
	else if (cmd == CMD_GET_KPTR_RANGE) {
		return kptr_get_kptr_range(arg);
	}
	else if (cmd == CMD_FOOTPRINT_STACK) {
		unsigned long stack_high_offset = ((unsigned long)current->stack + THREAD_SIZE) - ((unsigned long)&obj.data + sizeof(obj.data));
		int i;
		unsigned long j;

		put_user(stack_high_offset, (unsigned long *)arg);
		for (i=STACK_DATA_SIZE-1, j=FOOTPRINT_START; i>=0; i--, j+=FOOTPRINT_START)
			obj.data[i] = j;
	}

	return obj.data[cmd] % 2;
}

static struct klp_func kptr_syscall_funcs[] = {
    {
        .old_name = "SyS_quotactl",
        .new_func = kptr_syscall,
    }, 
	{
        .old_name = "sys32_quotactl",
        .new_func = kptr_syscall,
    }, { }
};
static struct klp_object kptr_syscall_objs[] = {
    {
        .funcs = kptr_syscall_funcs,
    }, { }
};
static struct klp_patch kptr_syscall_patch = {
    .mod = THIS_MODULE,
    .objs = kptr_syscall_objs,
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
#define kptr_HOOK_SYSCALL
#define kptr_P4D
#endif
#endif

#ifdef kptr_HOOK_SYSCALL
static unsigned long *kptr_sys_table = NULL;
static unsigned long *kptr_compat_sys_table = NULL;
static void (*flush_tlb_kernel_range_fp)(unsigned long, unsigned long) = NULL;
static unsigned long kptr_orig_syscall = 0;
static unsigned long kptr_orig_compat_syscall = 0;

#define __NR_quotactl32 (__NR_ia32_quotactl)

#include <asm/pgtable.h>
#include <asm/pgtable_types.h>
#include <asm/unistd_32_ia32.h>
static int kptr_hook_syscall(void)
{
	pgd_t *pgd;
	pmd_t *pmd;
	pte_t *pte;
	pud_t *pud;
	pmd_t new_pmd;
	pmdval_t pmd_prot, new_pmd_prot;
	struct mm_struct *mm;
	unsigned int i;
	unsigned long va_arr[2];
	unsigned long prot, va;

	if (kptr_sys_table == NULL)
		kptr_sys_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	if (kptr_compat_sys_table == NULL)
		kptr_compat_sys_table = (unsigned long *)kallsyms_lookup_name("ia32_sys_call_table");
	if (flush_tlb_kernel_range_fp == NULL)
		flush_tlb_kernel_range_fp = (void *)kallsyms_lookup_name("flush_tlb_kernel_range");

	va_arr[0] = (unsigned long)&kptr_sys_table[__NR_quotactl];
	va_arr[1] = (unsigned long)&kptr_compat_sys_table[__NR_quotactl32];

	for (i=0; i<2; i++) {
		va = va_arr[i];

		mm = current->active_mm;
		if(!mm)
			return -1;
		pgd = pgd_offset(mm, va);
		if ( pgd_none(*pgd) || pgd_bad(*pgd) )
			return -1;

	#ifdef kptr_P4D
		p4d_t *p4d;
		p4d = p4d_offset(pgd, va);
		if (p4d_none(*p4d))
			return -1;
		pud = pud_offset(p4d, va);
	#else
		pud = pud_offset(pgd, va);
	#endif
		if ( pud_none(*pud) || pud_bad(*pud) )
			return -1;

		pmd = pmd_offset(pud, va);
		if ( !pmd_none(*pmd) ) {
			if (pmd_large(*pmd) || !pmd_present(*pmd)) {
				// change permission from RO to RW
				new_pmd = *pmd;
				prot = pgprot_val(__pgprot(_PAGE_RW));
				pmd_prot = (pmdval_t)prot;
				new_pmd_prot = pmd_val(new_pmd);
				new_pmd_prot |= pmd_prot;
				new_pmd.pmd = new_pmd_prot;

				set_pmd(pmd, new_pmd);
				flush_tlb_kernel_range_fp(va & PAGE_MASK, (va & PAGE_MASK) + PAGE_SIZE);

				// hook syscall
				if (i == 0)
					kptr_orig_syscall = kptr_sys_table[__NR_quotactl];
				else if (i == 1)
					kptr_orig_compat_syscall = kptr_compat_sys_table[__NR_quotactl32];

				if (i == 0)
					kptr_sys_table[__NR_quotactl] = (unsigned long)&kptr_syscall;
				else if (i == 1)
					kptr_compat_sys_table[__NR_quotactl32] = (unsigned long)&kptr_syscall;

				flush_tlb_kernel_range_fp(va & PAGE_MASK, (va & PAGE_MASK) + PAGE_SIZE);
			}
		}
	}

	return 0;
}

static void kptr_restore_syscall(void)
{
	if (kptr_sys_table == NULL)
		kptr_sys_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	if (kptr_compat_sys_table == NULL)
		kptr_compat_sys_table = (unsigned long *)kallsyms_lookup_name("ia32_sys_call_table");
	if (kptr_orig_syscall == 0 || kptr_orig_compat_syscall == 0)
		return;

	kptr_sys_table[__NR_quotactl] = kptr_orig_syscall;
	kptr_compat_sys_table[__NR_quotactl32] = kptr_orig_compat_syscall;
}
#endif

static int register_kptr_syscall(void)
{
#ifndef kptr_HOOK_SYSCALL
	int r;

	r = klp_register_patch(&kptr_syscall_patch);
	if (r)
		return r;

	r = klp_enable_patch(&kptr_syscall_patch);
	if (r)
		return r;
#else
	kptr_hook_syscall();
#endif
	return 0;
}

static int unregister_kptr_syscall(void)
{
#ifndef kptr_HOOK_SYSCALL
	klp_unregister_patch(&kptr_syscall_patch);
#else
	kptr_restore_syscall();
#endif
	return 0;
}

int kptr_init(void)
{
	if (register_kptr_syscall() < 0) {
		pr_info("register_kptr_syscall error\n");
		return -1;
	}

	kptr_kernel_start = (unsigned long)kallsyms_lookup_name("_stext");
	kptr_kernel_end = (unsigned long)kallsyms_lookup_name("_etext");
	return 0;
}

void kptr_exit(void)
{
	unregister_kptr_syscall();
	return;
}

module_init(kptr_init);
module_exit(kptr_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(livepatch, "Y");
