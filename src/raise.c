#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

int main(int argc, char *argv[]) {
	char *fname;
	int fd;
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
	if (fd == -1) {
		fprintf(stderr, "Failed to open the file\n");
		exit(2);
	}
	fstat(fd, &fst);
	if (fst.st_size < sizeof(Elf32_Ehdr)) {
		fprintf(stderr, "File too small to be an ELF file\n");
		exit(4);
	}
	elf = mmap(NULL, fst.st_size, PROT_READ, MAP_SHARED, fd, 0);
	if (elf == NULL) {
		fprintf(stderr, "Failed to map file to memory\n");
		exit(5);
	}

	/* verify ELF magic numbers */
	if (elf->e_ident[EI_MAG0] != ELFMAG0) {
		fprintf(stderr, "Magic number verification failed\n");
		exit(6);
	}
	if (elf->e_ident[EI_MAG1] != ELFMAG1) {
		fprintf(stderr, "Magic number verification failed\n");
		exit(6);
	}
	if (elf->e_ident[EI_MAG2] != ELFMAG2) {
		fprintf(stderr, "Magic number verification failed\n");
		exit(6);
	}
}
