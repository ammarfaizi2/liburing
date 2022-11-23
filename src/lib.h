/* SPDX-License-Identifier: MIT */
#ifndef LIBURING_LIB_H
#define LIBURING_LIB_H

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "syscall.h"

#if defined(__x86_64__) || defined(__i386__)
#include "arch/x86/lib.h"
#elif defined(__aarch64__)
#include "arch/aarch64/lib.h"
#else
/*
 * We don't have nolibc support for this arch. Must use libc!
 */
#ifdef CONFIG_NOLIBC
#error "This arch doesn't support building liburing without libc"
#endif
/* libc wrappers. */
#include "arch/generic/lib.h"
#endif

#ifndef offsetof
#define offsetof(TYPE, FIELD) ((size_t) &((TYPE *)0)->FIELD)
#endif

#ifndef container_of
#define container_of(PTR, TYPE, FIELD) ({			\
	__typeof__(((TYPE *)0)->FIELD) *__FIELD_PTR = (PTR);	\
	(TYPE *)((char *) __FIELD_PTR - offsetof(TYPE, FIELD));	\
})
#endif

#define __maybe_unused		__attribute__((__unused__))
#define __hot			__attribute__((__hot__))
#define __cold			__attribute__((__cold__))

#ifdef CONFIG_NOLIBC
struct uring_heap {
	size_t		len;
	char		user_p[] __attribute__((__aligned__));
};

static inline void *__uring_malloc(size_t len)
{
	struct uring_heap *heap;

	heap = __sys_mmap(NULL, sizeof(*heap) + len, PROT_READ | PROT_WRITE,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (IS_ERR(heap))
		return NULL;

	heap->len = sizeof(*heap) + len;
	return heap->user_p;
}
#define malloc(LEN) __uring_malloc(LEN)

static inline void __uring_free(void *p)
{
	struct uring_heap *heap;

	if (uring_unlikely(!p))
		return;

	heap = container_of(p, struct uring_heap, user_p);
	__sys_munmap(heap, heap->len);
}
#define free(PTR) __uring_free(PTR)

static inline void *__uring_memset(void *s, int c, size_t n)
{
	unsigned char *p = s;
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (unsigned char) c;

	return s;
}
#define memset(S, C, N) __uring_memset(S, C, N)
#endif /* #ifdef CONFIG_NOLIBC */

#endif /* #ifndef LIBURING_LIB_H */
