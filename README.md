## Leak kernel pointer by exploiting uninitialized uses in Linux kernel

### Abstract

- The OS Kernel has always been a prime target for attackers.
  So that various mitigations have proposed and adopted in kernel.
  One of the mitigations is KASLR or Kernel Address Space Layout Randoization
  which mainly defeats code reuse attack by putting the kernel code on random address.
- With KASLR as a mitigation, Even if an attacker corrupts either return address or function pointer,
  the attacker can't set the address what he wants to jump to, because he doesn't know where the kernel code is.
- The one way to bypass KASLR is to leverage information leak vulnerability.
  The information leak can be disclosed by several root cause such as uninitialized use, buffer overread,
  use-after-free, logic errors. Among the causes, I mainly focuses on uninitialized use as happens most frequently in Linux kernel.
- I've conducted comprehensive study to find how to exploit the uninitialized use vulnerability to leak kernel pointer. As a result, I've developed KptrTools that is the set of tool to support an attacker to reach to successful exploitation.
- I've succeed to exploit a variety of real-world vulnerabilities using KptrTools.

### Directories

- tool/ :  KptrTools which includes KptrLib, KptrLkm, TinySysFuzz, ...
- exploit/ :  Real-world exploitation codes

### Slide

- Slide presented at Zer0Con 2019 [leak-kptr](https://jinb-park.github.io/leak-kptr.html)

### Contact

- jinb.park7@gmail.com
