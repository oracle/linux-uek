#ifndef KSPLICE_CLEAR_STACK_H_
# define KSPLICE_CLEAR_STACK_H_

/*
 * How many bytes to clear from the stack
 */
#define KSPLICE_CLEAR_STACK_BYTES 0x400

/*
 * Memset the stack
 */
static inline void ksplice_clear_stack(void)
{
	memset((void*)(current_stack_pointer - KSPLICE_CLEAR_STACK_BYTES),
	       0x0, KSPLICE_CLEAR_STACK_BYTES);
}


#endif /* !KSPLICE_CLEAR_STACK_H_ */
