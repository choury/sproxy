//
// auxv.h — ELF auxiliary vector constants for the BPF guest startup stack.
//
// 常量与 Linux 内核 <uapi/linux/auxvec.h> 一致；这里独立定义，
// 既供 VM 在 setup_stack 中合成 auxv，也供 musl/PDCLib 之类用户态 libc
// 在 crt0 里读取。用 #ifndef 守护以避免与宿主 <elf.h> 冲突。
//
#ifndef BPF_AUXV_H
#define BPF_AUXV_H

#ifndef AT_NULL
#define AT_NULL       0   /* 终止 auxv 数组的哨兵 */
#endif
#define AT_IGNORE      1
#define AT_EXECFD      2
#define AT_PHDR        3
#define AT_PHENT       4
#define AT_PHNUM       5
#define AT_PAGESIZE    6   /* 兼容命名（部分平台使用 AT_PAGESIZE） */
#ifndef AT_PAGESZ
#define AT_PAGESZ      6   /* 系统页大小 */
#endif
#define AT_BASE        7
#define AT_FLAGS       8
#define AT_ENTRY       9
#define AT_NOTELF      10
#define AT_UID         11  /* 真实 UID */
#define AT_EUID        12  /* 有效 UID */
#define AT_GID         13  /* 真实 GID */
#define AT_EGID        14  /* 有效 GID */
#define AT_PLATFORM    15  /* 指向平台标识字符串的指针 */
#define AT_HWCAP       16
#define AT_CLKTCK      17  /* times(2) 的时钟滴答频率 */
#define AT_SECURE     23   /* 是否运行在 setuid/setgid 受限环境 */
#define AT_RANDOM     25   /* 指向 16 字节随机数据用于栈 canary/PRNG */
#define AT_EXECFN     31   /* 指向可执行文件名字符串 */

#endif // BPF_AUXV_H