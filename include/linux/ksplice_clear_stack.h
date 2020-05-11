#ifndef KSPLICE_CLEAR_STACK_H_
# define KSPLICE_CLEAR_STACK_H_

/*
 * How many bytes to clear from the stack
 */
#define KSPLICE_CLEAR_STACK_BYTES 0x400

/*
 * Clear the stack, 64 bits at a time
 */
static inline void ksplice_clear_stack(void)
{
#ifdef CONFIG_MIPS
	unsigned long current_stack_pointer =
		(unsigned long)__builtin_frame_address(0);
#endif
	memset((void*)(current_stack_pointer - KSPLICE_CLEAR_STACK_BYTES),
	       0x0, KSPLICE_CLEAR_STACK_BYTES);
}


#endif /* !KSPLICE_CLEAR_STACK_H_ */
