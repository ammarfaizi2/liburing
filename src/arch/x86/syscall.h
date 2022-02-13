/* SPDX-License-Identifier: MIT */

#ifndef __INTERNAL__LIBURING_SYSCALL_H
	#error "This file should be included from src/syscall.h (liburing)"
#endif

#ifndef LIBURING_ARCH_X86_SYSCALL_H
#define LIBURING_ARCH_X86_SYSCALL_H

#if defined(__x86_64__)
/**
 * Note for syscall registers usage (x86-64):
 *   - %rax is the syscall number.
 *   - %rax is also the return value.
 *   - %rdi is the 1st argument.
 *   - %rsi is the 2nd argument.
 *   - %rdx is the 3rd argument.
 *   - %r10 is the 4th argument (**yes it's %r10, not %rcx!**).
 *   - %r8  is the 5th argument.
 *   - %r9  is the 6th argument.
 *
 * `syscall` instruction will clobber %r11 and %rcx.
 *
 * After the syscall returns to userspace:
 *   - %r11 will contain %rflags.
 *   - %rcx will contain the return address.
 *
 * IOW, after the syscall returns to userspace:
 *   %r11 == %rflags and %rcx == %rip.
 */

#define __do_syscall0(NUM) ({			\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"(NUM)	/* %rax */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall1(NUM, ARG1) ({		\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"((NUM)),	/* %rax */	\
		  "D"((ARG1))	/* %rdi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall2(NUM, ARG1, ARG2) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"((NUM)),	/* %rax */	\
		  "D"((ARG1)),	/* %rdi */	\
		  "S"((ARG2))	/* %rsi */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall3(NUM, ARG1, ARG2, ARG3) ({	\
	intptr_t rax;				\
						\
	__asm__ volatile(			\
		"syscall"			\
		: "=a"(rax)	/* %rax */	\
		: "a"((NUM)),	/* %rax */	\
		  "D"((ARG1)),	/* %rdi */	\
		  "S"((ARG2)),	/* %rsi */	\
		  "d"((ARG3))	/* %rdx */	\
		: "rcx", "r11", "memory"	\
	);					\
	rax;					\
})

#define __do_syscall4(NUM, ARG1, ARG2, ARG3, ARG4) ({			\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"((NUM)),	/* %rax */				\
		  "D"((ARG1)),	/* %rdi */				\
		  "S"((ARG2)),	/* %rsi */				\
		  "d"((ARG3)),	/* %rdx */				\
		  "r"(__r10)	/* %r10 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall5(NUM, ARG1, ARG2, ARG3, ARG4, ARG5) ({		\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"((NUM)),	/* %rax */				\
		  "D"((ARG1)),	/* %rdi */				\
		  "S"((ARG2)),	/* %rsi */				\
		  "d"((ARG3)),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8)	/* %r8 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#define __do_syscall6(NUM, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6) ({	\
	intptr_t rax;							\
	register __typeof__(ARG4) __r10 __asm__("r10") = (ARG4);	\
	register __typeof__(ARG5) __r8 __asm__("r8") = (ARG5);		\
	register __typeof__(ARG6) __r9 __asm__("r9") = (ARG6);		\
									\
	__asm__ volatile(						\
		"syscall"						\
		: "=a"(rax)	/* %rax */				\
		: "a"((NUM)),	/* %rax */				\
		  "D"((ARG1)),	/* %rdi */				\
		  "S"((ARG2)),	/* %rsi */				\
		  "d"((ARG3)),	/* %rdx */				\
		  "r"(__r10),	/* %r10 */				\
		  "r"(__r8),	/* %r8 */				\
		  "r"(__r9)	/* %r9 */				\
		: "rcx", "r11", "memory"				\
	);								\
	rax;								\
})

#else /* #if defined(__x86_64__) */

/**
 * Note for syscall registers usage (x86, 32-bit):
 *   - %eax is the syscall number.
 *   - %eax is also the return value.
 *   - %ebx is the 1st argument.
 *   - %ecx is the 2nd argument.
 *   - %edx is the 3rd argument.
 *   - %esi is the 4th argument.
 *   - %edi is the 5th argument.
 *   - %ebp is the 6th argument.
 */

#define __do_syscall0(NUM) ({			\
	intptr_t eax;				\
						\
	__asm__ volatile(			\
		"int	$0x80"			\
		: "=a"(eax)	/* %eax */	\
		: "a"(NUM)	/* %eax */	\
		: "memory"			\
	);					\
	eax;					\
})

#define __do_syscall1(NUM, ARG1) ({		\
	intptr_t eax;				\
						\
	__asm__ volatile(			\
		"int	$0x80"			\
		: "=a"(eax)	/* %eax */	\
		: "a"(NUM),	/* %eax */	\
		  "b"((ARG1))	/* %ebx */	\
		: "memory"			\
	);					\
	eax;					\
})

#define __do_syscall2(NUM, ARG1, ARG2) ({	\
	intptr_t eax;				\
						\
	__asm__ volatile(			\
		"int	$0x80"			\
		: "=a" (eax)	/* %eax */	\
		: "a"(NUM),	/* %eax */	\
		  "b"((ARG1)),	/* %ebx */	\
		  "c"((ARG2))	/* %ecx */	\
		: "memory"			\
	);					\
	eax;					\
})

#define __do_syscall3(NUM, ARG1, ARG2, ARG3) ({	\
	intptr_t eax;				\
						\
	__asm__ volatile(			\
		"int	$0x80"			\
		: "=a" (eax)	/* %eax */	\
		: "a"(NUM),	/* %eax */	\
		  "b"((ARG1)),	/* %ebx */	\
		  "c"((ARG2)),	/* %ecx */	\
		  "d"((ARG3))	/* %edx */	\
		: "memory"			\
	);					\
	eax;					\
})

#define __do_syscall4(NUM, ARG1, ARG2, ARG3, ARG4) ({	\
	intptr_t eax;					\
							\
	__asm__ volatile(				\
		"int	$0x80"				\
		: "=a" (eax)	/* %eax */		\
		: "a"(NUM),	/* %eax */		\
		  "b"((ARG1)),	/* %ebx */		\
		  "c"((ARG2)),	/* %ecx */		\
		  "d"((ARG3)),	/* %edx */		\
		  "S"((ARG4))	/* %esi */		\
		: "memory"				\
	);						\
	eax;						\
})

#define __do_syscall5(NUM, ARG1, ARG2, ARG3, ARG4, ARG5) ({	\
	intptr_t eax;						\
								\
	__asm__ volatile(					\
		"int	$0x80"					\
		: "=a" (eax)	/* %eax */			\
		: "a"(NUM),	/* %eax */			\
		  "b"((ARG1)),	/* %ebx */			\
		  "c"((ARG2)),	/* %ecx */			\
		  "d"((ARG3)),	/* %edx */			\
		  "S"((ARG4)),	/* %esi */			\
		  "D"((ARG5))	/* %edi */			\
		: "memory"					\
	);							\
	eax;							\
})

/*
 * __do_syscall6() on x86 32-bit is a mess.
 *
 * Both Clang and GCC cannot use %ebp in the clobber list and "r" constraint
 * without -fomit-frame-pointer.
 *
 * Current implementation:
 *
 * For clang (the Assembly statement can't clobber %ebp):
 *   1) Push %ebp to preserve its value on the stack.
 *   2) Move the 6th argument of syscall from memory to %ebp.
 *   3) Do the syscall (int $0x80).
 *   4) Pop %ebp to restore the %ebp value.
 *
 * For GCC, fortunately it has #pragma that can force a specific function
 * to be compiled with -fomit-frame-pointer, so it can use "r"(var) where
 * var is a variable bound to %ebp.
 *
 * If you have a better approach for this, please mail me.
 *
 *   To: io-uring Mailing List <io-uring@vger.kernel.org>
 *   Cc: Ammar Faizi <ammarfaizi2@gnuweeb.org>
 *
 */
#if defined(__clang__)
static inline intptr_t ____do_syscall6(intptr_t eax, intptr_t ebx, intptr_t ecx,
				       intptr_t edx, intptr_t esi, intptr_t edi,
				       intptr_t ebp)
{
	__asm__ volatile(
		"pushl	%%ebp\n\t"
		"movl	%[arg6], %%ebp\n\t"
		"int	$0x80\n\t"
		"popl	%%ebp\n\t"
		: "=a" (eax)		/* %eax */
		: "a"(eax),		/* %eax */
		  "b"(ebx),		/* %ebx */
		  "c"(ecx),		/* %ecx */
		  "d"(edx),		/* %edx */
		  "S"(esi),		/* %esi */
		  "D"(edi),		/* %edi */
		  [arg6]"m"(ebp)	/* %ebp */
		: "memory"
	);
	return eax;
}
#else /* #if defined(__clang__) */
#pragma GCC push_options
#pragma GCC optimize "-fomit-frame-pointer"
static inline intptr_t ____do_syscall6(intptr_t eax, intptr_t ebx, intptr_t ecx,
				       intptr_t edx, intptr_t esi, intptr_t edi,
				       intptr_t ebp)
{
	register intptr_t __ebp __asm__("ebp") = ebp;
	__asm__ volatile(
		"int	$0x80"
		: "=a" (eax)	/* %eax */
		: "a"(eax),	/* %eax */
		  "b"(ebx),	/* %ebx */
		  "c"(ecx),	/* %ecx */
		  "d"(edx),	/* %edx */
		  "S"(esi),	/* %esi */
		  "D"(edi),	/* %edi */
		  "r"(__ebp)	/* %ebp */
		: "memory"
	);
	return eax;
}
#pragma GCC pop_options
#endif /* #if defined(__clang__) */

#define __do_syscall6(NUM, ARG1, ARG2, ARG3, ARG4, ARG5, ARG6) (		\
    ____do_syscall6((intptr_t) (NUM), (intptr_t) (ARG1), (intptr_t) (ARG2),	\
                    (intptr_t) (ARG3), (intptr_t) (ARG4),			\
                    (intptr_t) (ARG5), (intptr_t) (ARG6))			\
)

#endif /* #if defined(__x86_64__) */

#endif /* #ifndef LIBURING_ARCH_X86_SYSCALL_H */
