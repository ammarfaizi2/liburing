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

#endif /* #ifndef LIBURING_ARCH_GENERIC_SYSCALL_H */
