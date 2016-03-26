#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

void error(char *message) {
	fprintf(stderr, "%s\n", message);
	exit(1);
}

int main(int argc, char *argv[]) {
	char *fname;
	int fd, i;
	struct stat fst;
	Elf32_Ehdr *elf;

	/* parse arguments */
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <dumpfile>\n", argv[0]);
		exit(1);
	}
	fname = argv[1];

	/* map file to memory */
	fd = open(fname, O_RDONLY);
	if (fd == -1) error("Failed to open the file");
	fstat(fd, &fst);
	if (fst.st_size < sizeof(Elf32_Ehdr)) error("Not an ELF");
	elf = mmap(NULL, fst.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (elf == NULL) error("Failed to map file to memory");

	/* verify ELF */
	if (elf->e_ident[EI_MAG0] != ELFMAG0
			|| elf->e_ident[EI_MAG1] != ELFMAG1
			|| elf->e_ident[EI_MAG2] != ELFMAG2
			|| elf->e_ident[EI_MAG3] != ELFMAG3)
		error("Not an ELF");
	if (elf->e_type != ET_CORE) error("Not a core ELF");
	if (elf->e_machine != EM_386) error("Bad machine");
	if (elf->e_version != EV_CURRENT) error("Bad version");

	/* read ELF */
	for (i = 0; i < elf->e_phnum; ++i) {
		Elf32_Phdr *ph = (void *) elf
			+ elf->e_phoff + i * elf->e_phentsize;

		printf("\nProgram Header %d\n", i);
		if (ph->p_type == PT_LOAD)
			printf("type load\n");
		else if (ph->p_type == PT_NOTE)
			printf("type note\n");
		else
			printf("type %d\n", ph->p_type);

		printf("p_offset\t%d\n", ph->p_offset);
		printf("p_vaddr\t%d\n", ph->p_vaddr);
		printf("p_filesz\t%d\n", ph->p_filesz);
		printf("p_memsz\t%d\n", ph->p_memsz);
		printf("p_flags\t%d\n", ph->p_flags);
		printf("p_align\t%d\n", ph->p_align);
	}
	printf("e_phoff %d\n", elf->e_phoff);
	printf("e_phentsize %d\n", elf->e_phentsize);
	printf("e_phnum %d\n", elf->e_phnum);
}
