/* SPDX-License-Identifier: MIT */

#include "lib.h"
#include "syscall.h"
#include <liburing.h>

int io_uring_enter(unsigned int fd, unsigned int to_submit,
		   unsigned int min_complete, unsigned int flags,
		   sigset_t *sig)
{
	return __sys_io_uring_enter(fd, to_submit, min_complete, flags, sig);
}

int io_uring_enter2(int fd, unsigned to_submit, unsigned min_complete,
		    unsigned flags, sigset_t *sig, int sz)
{
	return __sys_io_uring_enter2(fd, to_submit, min_complete, flags, sig,
				     sz);
}

int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
	return __sys_io_uring_setup(entries, p);
}

int io_uring_register(int fd, unsigned opcode, const void *arg,
		      unsigned nr_args)
{
	return __sys_io_uring_register(fd, opcode, arg, nr_args);
}
