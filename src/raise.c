#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/procfs.h>

#define ALIGN4(value) (((value) + 3) & (~3) )
#define PT_ANY -1

typedef struct {
	long prstatus;
	long file;
	long tls;
} notes_desc_offsets_t;

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

void for_each_segment(FILE *f, Elf32_Word type, void *result,
		void (*func)(FILE*, Elf32_Phdr*, void*)) {
	int i;
	Elf32_Ehdr hdr;

	read_header(f, &hdr);
	for (i = 0; i < hdr.e_phnum; ++i) {
		Elf32_Phdr phdr;
		read_at(f, hdr.e_phoff + i * hdr.e_phentsize, &phdr,
				sizeof(Elf32_Phdr), 1);
		if (phdr.p_type == type || type == PT_ANY)
			(*func)(f, &phdr, result);
	}
}

void process_load_segment(FILE *f, Elf32_Phdr *phdr, void *result) {
	// TODO
	printf("Load segment\n");
	printf("p_offset\t%d\n", phdr->p_offset);
	printf("p_vaddr\t%d\n", phdr->p_vaddr);
	printf("p_filesz\t%d\n", phdr->p_filesz);
	printf("p_memsz\t%d\n", phdr->p_memsz);
	printf("p_flags\t%d\n", phdr->p_flags);
	printf("p_align\t%d\n", phdr->p_align);
	printf("\n");
}

void gather_relevant_notes(FILE *f, Elf32_Phdr *phdr, void *result) {
	int note_hdr[3]; /* note header: name size, desc size, type */
	long desc_offset, offset;
	notes_desc_offsets_t *desc_offsets = result;

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
			desc_offsets->prstatus = desc_offset;
			break;
		case NT_FILE:
			desc_offsets->file= desc_offset;
			break;
		case NT_386_TLS:
			desc_offsets->tls = desc_offset;
			break;
		}
	}
}

void map_files(FILE *f, long nt_file_desc_offset) {
	unsigned hdr[2]; /* count, page size (unit for file offset) */
	unsigned long entry[3]; /* start, end, file offset */
	char fname[256];
	long entry_offset, fname_offset;
	int i;

	read_at(f, nt_file_desc_offset, hdr, sizeof(hdr), 1);
	entry_offset = nt_file_desc_offset + sizeof(hdr);
	fname_offset = entry_offset + hdr[0] * sizeof(entry);

	for (i = 0; i < hdr[0]; ++i) {
		read_at(f, entry_offset, entry, sizeof(entry), 1);
		read_at(f, fname_offset, fname, 1, sizeof(fname));
		fname[sizeof(fname) - 1] = '\0';

		printf("%10lx %10lx %10lu %s\n",
				entry[0], entry[1], entry[2], fname);
		// TODO

		entry_offset += sizeof(entry);
		fname_offset += strlen(fname) + 1;
	}
}


int main(int argc, char *argv[]) {
	FILE *f;
	notes_desc_offsets_t nd_offsets;
	struct elf_prstatus prstatus;

	if (argc != 2) error("Supply exactly one argument (core file name)");
	f = fopen(argv[1], "r");
	if (f == NULL) error("Failed to open the file");

	verify_header(f);
	for_each_segment(f, PT_NOTE, &nd_offsets, gather_relevant_notes);
	for_each_segment(f, PT_LOAD, NULL, process_load_segment);

	map_files(f, nd_offsets.file);

	read_at(f, nd_offsets.prstatus, &prstatus, sizeof(prstatus_t), 1);
	fclose(f);

	/* pr_reg is an array of registered order as in user_regs_struct */
	printf("EAX: %lu\n", prstatus.pr_reg[6]);
	printf("EBX: %lu\n", prstatus.pr_reg[0]);
	printf("ECX: %lu\n", prstatus.pr_reg[1]);
	printf("EDX: %lu\n", prstatus.pr_reg[2]);
	printf("ESI: %lu\n", prstatus.pr_reg[3]);
	printf("EDI: %lu\n", prstatus.pr_reg[4]);
	printf("EBP: 0x%lx\n", prstatus.pr_reg[5]);
	printf("ESP: 0x%lx\n", prstatus.pr_reg[15]);
	printf("EIP: 0x%lx\n", prstatus.pr_reg[12]);
	printf("EFLAGS: %lu\n", prstatus.pr_reg[14]);
	// TODO

}
