#ifndef __CTF_API_H_
#define __CTF_API_H_

/*
 * The CTF data model is inferred to be the caller's data model or the data
 * model of the given object, unless ctf_setmodel() is explicitly called.
 */
#define CTF_MODEL_ILP32		1	/* object data model is ILP32 */
#define CTF_MODEL_LP64		2	/* object data model is LP64 */
#ifdef CONFIG_64BIT
# define CTF_MODEL_NATIVE	CTF_MODEL_LP64
#else
# define CTF_MODEL_NATIVE	CTF_MODEL_ILP32
#endif

#endif /* __CTF_API_H_ */
