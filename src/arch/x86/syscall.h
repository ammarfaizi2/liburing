/* SPDX-License-Identifier: MIT */

#ifndef LIBURING_SYSCALL_H
#  error "This file should be included from src/syscall.h (liburing)"
#endif

#ifndef LIBURING_ARCH_X86_SYSCALL_H
#define LIBURING_ARCH_X86_SYSCALL_H

#if defined(__x86_64__)
/**
 * Note for syscall register usage (x86-64):
 *   - %rax is the syscall number.
 *   - %rax is also the return value.
 *   - %rdi is the 1st argument.
 *   - %rsi is the 2nd argument.
 *   - %rdx is the 3rd argument.
 *   - %r10 is the 4th argument (**yes %r10, not %rcx!**).
 *   - %r8  is the 5th argument.
 *   - %r9  is the 6th argument.
 *
 * `syscall` instruction will clobber %r11 and %rcx.
 *
 * After the syscall returns to userspace:
 *   - %r11 will contain %rflags.
 *   - %rcx will contain the return address.
 *
 * -- 
 * Ammar
 */

static inline void *__arch_impl_mmap(void *addr, size_t length, int prot,
				     int flags, int fd, off_t offset)
{
	void *rax;
	register int r10 __asm__("r10") = flags;
	register int r8 __asm__("r8") = fd;
	register int r9 __asm__("r9") = offset;

	__asm__ volatile(
		"syscall"
		: "=a"(rax)
		: "a"(__NR_mmap),	/* %rax */
		  "D"(addr),		/* %rdi */
		  "S"(length),		/* %rsi */
		  "d"(prot),		/* %rdx */
		  "r"(r10),		/* %r10 */
		  "r"(r8),		/* %r8  */
		  "r"(r9)		/* %r9  */
		: "memory", "rcx", "r11"
	);
	return rax;
}

static inline int __arch_impl_munmap(void *addr, size_t length)
{
	int eax;

	__asm__ volatile(
		"syscall"
		: "=a"(eax)		/* %rax */
		: "a"(__NR_munmap),	/* %rax */
		  "D"(addr),		/* %rdi */
		  "S"(length)		/* %rsi */
		: "memory", "rcx", "r11"
	);
	return eax;
}

static inline int __arch_impl_madvise(void *addr, size_t length, int advice)
{
	int eax;

	__asm__ volatile(
		"syscall"
		: "=a"(eax)		/* %rax */
		: "a"(__NR_madvise),	/* %rax */
		  "D"(addr),		/* %rdi */
		  "S"(length),		/* %rsi */
		  "d"(advice)		/* %rdx */
		: "memory", "rcx", "r11"
	);
	return eax;
}

static inline int __arch_impl_getrlimit(int resource, struct rlimit *rlim)
{
	int eax;

	__asm__ volatile(
		"syscall"
		: "=a"(eax)		/* %rax */
		: "a"(__NR_getrlimit),	/* %rax */
		  "D"(resource),	/* %rdi */
		  "S"(rlim)		/* %rsi */
		: "memory", "rcx", "r11"
	);
	return eax;
}

static inline int __arch_impl_setrlimit(int resource, const struct rlimit *rlim)
{
	int eax;

	__asm__ volatile(
		"syscall"
		: "=a"(eax)		/* %rax */
		: "a"(__NR_setrlimit),	/* %rax */
		  "D"(resource),	/* %rdi */
		  "S"(rlim)		/* %rsi */
		: "memory", "rcx", "r11"
	);
	return eax;
}

static inline int __arch_impl_io_uring_register(int fd, unsigned opcode,
						const void *arg,
						unsigned nr_args)
{
	int eax;
	register unsigned r10 __asm__("r10") = nr_args;

	__asm__ volatile(
		"syscall"
		: "=a"(eax)			/* %rax */
		: "a"(__NR_io_uring_register),	/* %rax */
		  "D"(fd),			/* %rdi */
		  "S"(opcode),			/* %rsi */
		  "d"(arg),			/* %rdx */
		  "r"(r10)			/* %r10 */
		: "memory", "rcx", "r11"
	);
	return eax;
}

static inline int __arch_impl_io_uring_setup(unsigned entries,
					     struct io_uring_params *p)
{
	int eax;

	__asm__ volatile(
		"syscall"
		: "=a"(eax)			/* %rax */
		: "a"(__NR_io_uring_setup),	/* %rax */
		  "D"(entries),			/* %rdi */
		  "S"(p)			/* %rsi */
		: "memory", "rcx", "r11"
	);
	return eax;
}

static inline int __arch_impl_io_uring_enter(int fd, unsigned to_submit,
					     unsigned min_complete,
					     unsigned flags, sigset_t *sig,
					     int sz)
{
	int eax;
	register unsigned r10 __asm__("r10") = flags;
	register sigset_t *r8 __asm__("r8") = sig;
	register int r9 __asm__("r9") = sz;

	__asm__ volatile(
		"syscall"
		: "=a"(eax)
		: "a"(__NR_io_uring_enter),	/* %rax */
		  "D"(fd),			/* %rdi */
		  "S"(to_submit),		/* %rsi */
		  "d"(min_complete),		/* %rdx */
		  "r"(r10),			/* %r10 */
		  "r"(r8),			/* %r8  */
		  "r"(r9)			/* %r9  */
		: "memory", "rcx", "r11"
	);
	return eax;
}

#else /* #if defined(__x86_64__) */

/*
 * TODO: Add x86 (32-bit) support here.
 */
#error "x86 (32-bit) is currently not supported"

#endif /* #if defined(__x86_64__) */

#endif /* #ifndef LIBURING_ARCH_X86_SYSCALL_H */
