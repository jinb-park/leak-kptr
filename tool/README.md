## KptrTools

### Setup

1. ./build.sh
2. ./setup.sh

### Footprinting kernel stack with KptrLib

- Just add call KptrLib function to your exploit code.
- Example (Assume Leak Size is 4 byte). Below example can be applied to both normal-mode and compat-mode.
```
#include <kptr-lib.h>  // kptr-lib.h includes functions needed for footprinting.
...
int main(int argc, char **argv)
{
	int r;
	unsigned long long leak_offset, stack_offset;
	unsigned int leak_value;
	int leak_size = 4;
	...
	// 1. Footprinting kernel stack
	r = kptr_api_footprint_stack(&stack_offset);

	// 2. Trigger vulnerability.
	leak_value = trigger_vulnerability();

	// 3. Get leak offset. You must specify proper leak_size, leak_value, stack_offset.
	leak_offset = kptr_api_get_leak_offset(leak_size, leak_value, stack_offset);
	printf("leak_offset : %lld\n", leak_offset);
	...
}
```

### How to use TinySysFuzz for successful exploitation

- Run TinySysFuzz
```
1. cd tiny-sys-fuzz
2. ./tiny-sys-fuzz  (run tiny-sys-fuzz)
3. vim out.csv  (check the result)
```

- Pick an proper KptrEntry
  - Assume that the Leak Offset is 296.
  - Find an KptrEntry of which Leak Offset is 296. (in out.csv)
  - Pick the KptrEntry as belows.
    - access,0,15,0,296,ffffffffba8a80cd,402f7b,4,0,0,0,0 
      - (system call name, pointer type, id, sub-id, offset, pointer value, system call arguments)

- Put sensitive kernel pointer on the Leak Offset by calling the KptrEntry.
```
int main(int argc, char **argv)
{
	...
	// 1. Call the KptrEntry for putting sensitive kernel pointer on the Leak Offset.
	access("/proc/iomem", R_OK);

	// 2. Trigger vulnerability.
	leak_value = trigger_vulnerability();

	// 3. Check leak_value
	// The result will be same to KptrEntry's pointer value. (ffffffffba8a80cd)
	printf("leak_value : %ld\n", leak_value);
	...
}
```

### How to use TinySysFuzz for exploitation on compat-mode

- Run TinySysFuzz32
```
1. cd tiny-sys-fuzz
2. ./tiny-sys-fuzz32  (run tiny-sys-fuzz32)
3. vim out.csv  (check the result)
```

- Next steps are perfectly same to "How to use TinySysFuzz for successful exploitation".

### How to integrate KptrFuzz into Linux Test Project (LTP)

- I've integrated KptrFuzz into Linux Test Project based on the below commit.
  - Link :  https://github.com/linux-test-project/ltp/commit/3373bb3f
  - Commit ID :  3373bb3f05f340c07abbdfc48ca45c3acf1c2a4b

- Instructions for integration & build
  - "Setup" phase must be pre-performed.
```
1. git clone https://github.com/linux-test-project/ltp.git
2. cd ltp
3. git checkout 3373bb3f05f340c07abbdfc48ca45c3acf1c2a4b
4. make autotools
5. ./configure
6. rm -f include/lapi/syscalls.h
7. git am 0001-Integrate-with-KptrFuzz.patch (under tool/linux-test-project/)
8. make
9. sudo make install
```

- Run LTP & Check the result of KptrFuzz
```
1. sudo mkdir /opt/kptr
2. cd /opt/ltp
3. sudo ./runltp -f syscalls  (Wait some minutes..)
4. ls -l /opt/kptr (Check the result)
  - e.g) "976_0.csv" means file which contains a number of KptrEntry of which LeakOffset is 976, Type is Kernel code.
```




