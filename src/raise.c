#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define ALIGN4(value) (((value) + 3) & (~3) )
#define PT_ANY -1

void error(char *msg) {
	fprintf(stderr, "%s\n", msg);
	exit(1);
}

int read_at(FILE *f, long offset, void *ptr, size_t size, size_t nmemb) {
	fseek(f, offset, SEEK_SET);
	return fread(ptr, size, nmemb, f);
}

void read_header(FILE *f, Elf32_Ehdr *hdr) {
	if (read_at(f, 0, hdr, sizeof(Elf32_Ehdr), 1) != 1)
		error("Failed to read ELF header");
}

void verify_header(FILE *f) {
	Elf32_Ehdr hdr;

	read_header(f, &hdr);
	if (hdr.e_ident[EI_MAG0] != ELFMAG0
			|| hdr.e_ident[EI_MAG1] != ELFMAG1
			|| hdr.e_ident[EI_MAG2] != ELFMAG2
			|| hdr.e_ident[EI_MAG3] != ELFMAG3)
		error("Not an ELF");
	if (hdr.e_type != ET_CORE) error("Not a core ELF");
	if (hdr.e_machine != EM_386) error("Bad machine");
	if (hdr.e_version != EV_CURRENT) error("Bad version");
}

void for_each_segment(FILE *f, Elf32_Word type,
		void (*func)(FILE*, Elf32_Phdr*)) {
	int i;
	Elf32_Ehdr hdr;

	read_header(f, &hdr);
	for (i = 0; i < hdr.e_phnum; ++i) {
		Elf32_Phdr phdr;
		read_at(f, hdr.e_phoff + i * hdr.e_phentsize, &phdr,
				sizeof(Elf32_Phdr), 1);
		if (phdr.p_type == type || type == PT_ANY)
			(*func)(f, &phdr);
	}
}

void verify_segment_type(FILE *f, Elf32_Phdr *phdr) {
	switch (phdr->p_type) {
	case PT_LOAD:
	case PT_NOTE:
		break;
	default:
		error("Unknown segment type");
	}
}

void handle_load_segment(FILE *f, Elf32_Phdr *phdr) {
	printf("Load segment\n");
	printf("p_offset\t%d\n", phdr->p_offset);
	printf("p_vaddr\t%d\n", phdr->p_vaddr);
	printf("p_filesz\t%d\n", phdr->p_filesz);
	printf("p_memsz\t%d\n", phdr->p_memsz);
	printf("p_flags\t%d\n", phdr->p_flags);
	printf("p_align\t%d\n", phdr->p_align);
	printf("\n");
}

void handle_notes_segment(FILE *f, Elf32_Phdr *phdr) {
	int note_hdr[3]; /* note header: name size, desc size, type */
	int desc_offset, offset;

	offset = phdr->p_offset;
	while (offset < phdr->p_offset + phdr->p_filesz) {
		read_at(f, offset, note_hdr, sizeof(note_hdr), 1);

		// offset at current note
		offset += sizeof(note_hdr);
		// offset at name
		offset += note_hdr[0];
		offset = ALIGN4(offset);
		// offset at desc
		desc_offset = offset;
		offset += note_hdr[1];
		offset = ALIGN4(offset);
		// offset at next note

		switch (note_hdr[2]) {
		case NT_PRSTATUS:
		case NT_FPREGSET:
		case NT_PRPSINFO:
		case NT_AUXV:
		case NT_SIGINFO:
		case NT_FILE:
		case NT_PRXFPREG:
		case NT_386_TLS:
		case NT_X86_XSTATE:
			printf("Found known note: 0x%x\n", note_hdr[2]);
			break;
		default:
			error("Unknown note type");
		}
	}
}

int main(int argc, char *argv[]) {
	FILE *f;

	if (argc != 2) error("Supply exactly one argument (core file name)");
	f = fopen(argv[1], "r");
	if (f == NULL) error("Failed to open the file");
	verify_header(f);
	for_each_segment(f, PT_ANY, verify_segment_type);
	for_each_segment(f, PT_LOAD, handle_load_segment);
	for_each_segment(f, PT_NOTE, handle_notes_segment);
	fclose(f);
}
