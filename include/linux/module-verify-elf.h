#ifdef CONFIG_64BIT

#define Elf_Sym Elf64_Sym
#define Elf_Shdr Elf64_Shdr
#define Elf_Ehdr Elf64_Ehdr
#define Elf_Phdr Elf64_Phdr
#define Elf_Dyn Elf64_Dyn
#define Elf_Rel Elf64_Rel
#define Elf_Rela Elf64_Rela
#define ELF_R_SYM   ELF64_R_SYM
#define ELF_R_TYPE  ELF64_R_TYPE

#define MODULES_ARE_ELF64

#else

#define Elf_Sym Elf32_Sym
#define Elf_Shdr Elf32_Shdr
#define Elf_Ehdr Elf32_Ehdr
#define Elf_Phdr Elf32_Phdr
#define Elf_Dyn Elf32_Dyn
#define Elf_Rel Elf32_Rel
#define Elf_Rela Elf32_Rela
#define ELF_R_SYM   ELF32_R_SYM
#define ELF_R_TYPE  ELF32_R_TYPE

#define MODULES_ARE_ELF32

#endif
