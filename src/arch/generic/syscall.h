/* SPDX-License-Identifier: MIT */

#ifndef __INTERNAL__LIBURING_SYSCALL_H
	#error "This file should be included from src/syscall.h (liburing)"
#endif

#ifndef LIBURING_ARCH_GENERIC_SYSCALL_H
#define LIBURING_ARCH_GENERIC_SYSCALL_H
/*
 * This file contains syscall libc wrapper.
 *
 * man 2 syscall:
 * The return value is defined by the system call being invoked. In general,
 * a 0 return value indicates success. A -1 return value indicates an error,
 * and an error number is stored in errno.
 */

#define __do_syscall0(NUM) ({		\
	intptr_t ret;			\
	ret = syscall((NUM));		\
	((ret == -1) ? -errno : ret);	\
})

#define __do_syscall1(NUM, ARG1) ({	\
	intptr_t ret;			\
	ret = syscall((NUM), (ARG1));	\
	((ret == -1) ? -errno : ret);	\
})

#define __do_syscall2(NUM, ARG1, ARG2) ({	\
	intptr_t ret;				\
	ret = syscall((NUM), (ARG1), (ARG2));	\
	((ret == -1) ? -errno : ret);		\
})

#define __do_syscall3(NUM, ARG1, ARG2, ARG3) ({		\
	intptr_t ret;					\
	ret = syscall((NUM), (ARG1), (ARG2), (ARG3));	\
	((ret == -1) ? -errno : ret);			\
})

#define __do_syscall4(NUM, ARG1, ARG2, ARG3, ARG4) ({		\
	intptr_t ret;						\
	ret = syscall((NUM), (ARG1), (ARG2), (ARG3), (ARG4));	\
	((ret == -1) ? -errno : ret);				\
})

#define __do_syscall5(NUM, ARG1, ARG2, ARG3, ARG4, ARG5) ({		\
	intptr_t ret;							\
	ret = syscall((NUM), (ARG1), (ARG2), (ARG3), (ARG4), (ARG5));	\
	((ret == -1) ? -errno : ret);					\
})

#define __do_syscall6(NUM, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6) ({		\
	intptr_t ret;								\
	ret = syscall((NUM), (ARG1), (ARG2), (ARG3), (ARG4), (ARG5), (ARG6));	\
	((ret == -1) ? -errno : ret);						\
})

static inline int ____sys_io_uring_register(int fd, unsigned opcode,
					    const void *arg, unsigned nr_args)
{
	int ret;
	ret = syscall(__NR_io_uring_register, fd, opcode, arg, nr_args);
	return (ret < 0) ? -errno : ret;
}

static inline int ____sys_io_uring_setup(unsigned entries,
					 struct io_uring_params *p)
{
	int ret;
	ret = syscall(__NR_io_uring_setup, entries, p);
	return (ret < 0) ? -errno : ret;
}

static inline int ____sys_io_uring_enter2(int fd, unsigned to_submit,
					  unsigned min_complete, unsigned flags,
					  sigset_t *sig, int sz)
{
	int ret;
	ret = syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
		      sig, sz);
	return (ret < 0) ? -errno : ret;
}

static inline int ____sys_io_uring_enter(int fd, unsigned to_submit,
					 unsigned min_complete, unsigned flags,
					 sigset_t *sig)
{
	return ____sys_io_uring_enter2(fd, to_submit, min_complete, flags, sig,
				       _NSIG / 8);
}

static inline void *__sys_mmap(void *addr, size_t length, int prot, int flags,
			       int fd, off_t offset)
{
	void *ret;
	ret = mmap(addr, length, prot, flags, fd, offset);
	return (ret == MAP_FAILED) ? ERR_PTR(-errno) : ret;
}

static inline int __sys_munmap(void *addr, size_t length)
{
	int ret;
	ret = munmap(addr, length);
	return (ret < 0) ? -errno : ret;
}

static inline int __sys_madvise(void *addr, size_t length, int advice)
{
	int ret;
	ret = madvise(addr, length, advice);
	return (ret < 0) ? -errno : ret;
}

static inline int __sys_getrlimit(int resource, struct rlimit *rlim)
{
	int ret;
	ret = getrlimit(resource, rlim);
	return (ret < 0) ? -errno : ret;
}

static inline int __sys_setrlimit(int resource, const struct rlimit *rlim)
{
	int ret;
	ret = setrlimit(resource, rlim);
	return (ret < 0) ? -errno : ret;
}

static inline int __sys_close(int fd)
{
	int ret;
	ret = close(fd);
	return (ret < 0) ? -errno : ret;
}

#endif /* #ifndef LIBURING_ARCH_GENERIC_SYSCALL_H */
