/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_SYSCALL_H
#define LIBURING_SYSCALL_H

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/resource.h>

#include <liburing.h>

#ifdef __alpha__
/*
 * alpha and mips are exception, other architectures have
 * common numbers for new system calls.
 */
# ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup		535
# endif
# ifndef __NR_io_uring_enter
#  define __NR_io_uring_enter		536
# endif
# ifndef __NR_io_uring_register
#  define __NR_io_uring_register	537
# endif
#elif defined __mips__
# ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup		(__NR_Linux + 425)
# endif
# ifndef __NR_io_uring_enter
#  define __NR_io_uring_enter		(__NR_Linux + 426)
# endif
# ifndef __NR_io_uring_register
#  define __NR_io_uring_register	(__NR_Linux + 427)
# endif
#else /* !__alpha__ and !__mips__ */
# ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup		425
# endif
# ifndef __NR_io_uring_enter
#  define __NR_io_uring_enter		426
# endif
# ifndef __NR_io_uring_register
#  define __NR_io_uring_register	427
# endif
#endif

struct io_uring_params;

static inline void *ERR_PTR(intptr_t n)
{
	return (void *) n;
}

static inline intptr_t PTR_ERR(const void *ptr)
{
	return (intptr_t) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return uring_unlikely((uintptr_t) ptr >= (uintptr_t) -4095UL);
}

#define __INTERNAL__LIBURING_SYSCALL_H
#if defined(__x86_64__) || defined(__i386__)
	#include "arch/x86/syscall.h"
#else
	/*
	 * We don't have native syscall wrappers
	 * for this arch. Must use libc!
	 */
	#ifdef CONFIG_NOLIBC
		#error "This arch doesn't support building liburing without libc"
	#endif
	/* libc syscall wrappers. */
	#include "arch/generic/syscall.h"
#endif
#undef __INTERNAL__LIBURING_SYSCALL_H


static inline void *__sys_mmap(void *addr, size_t length, int prot, int flags,
			       int fd, off_t offset)
{
	return (void *) __do_syscall6(__NR_mmap, addr, length, prot, flags, fd,
				      offset);
}

static inline int __sys_munmap(void *addr, size_t length)
{
	return (int) __do_syscall2(__NR_munmap, addr, length);
}

static inline int __sys_madvise(void *addr, size_t length, int advice)
{
	return (int) __do_syscall2(__NR_madvise, addr, length);
}

static inline int __sys_getrlimit(int resource, struct rlimit *rlim)
{
	return (int) __do_syscall2(__NR_getrlimit, resource, rlim);
}

static inline int __sys_setrlimit(int resource, const struct rlimit *rlim)
{
	return (int) __do_syscall2(__NR_setrlimit, resource, rlim);
}

static inline int __sys_close(int fd)
{
	return (int) __do_syscall1(__NR_close, fd);
}

static inline int ____sys_io_uring_register(int fd, unsigned opcode,
					    const void *arg, unsigned nr_args)
{
	return (int) __do_syscall4(__NR_io_uring_register, fd, opcode, arg,
				   nr_args);
}

static inline int ____sys_io_uring_setup(unsigned entries,
					 struct io_uring_params *p)
{
	return (int) __do_syscall2(__NR_io_uring_setup, entries, p);
}

static inline int ____sys_io_uring_enter2(int fd, unsigned to_submit,
					  unsigned min_complete, unsigned flags,
					  sigset_t *sig, int sz)
{
	return (int) __do_syscall6(__NR_io_uring_enter, fd, to_submit,
				   min_complete, flags, sig, sz);
}

static inline int ____sys_io_uring_enter(int fd, unsigned to_submit,
					 unsigned min_complete, unsigned flags,
					 sigset_t *sig)
{
	return ____sys_io_uring_enter2(fd, to_submit, min_complete, flags, sig,
				       _NSIG / 8);
}

/*
 * For backward compatibility.
 * (these __sys* functions always use libc, see syscall.c)
 */
int __sys_io_uring_setup(unsigned entries, struct io_uring_params *p);
int __sys_io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
			 unsigned flags, sigset_t *sig);
int __sys_io_uring_enter2(int fd, unsigned to_submit, unsigned min_complete,
			  unsigned flags, sigset_t *sig, int sz);
int __sys_io_uring_register(int fd, unsigned int opcode, const void *arg,
			    unsigned int nr_args);

#endif
