#include <asm/ldt.h>
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/procfs.h>
#include <ucontext.h>

#define ALIGN4(value) (((value) + 3) & (~3) )
#define FILENAME_SIZE 256
#define NOTE_FILE_ENTRY_SIZE (3 * sizeof(unsigned long))

/* stack and context */
char stack[16384];
ucontext_t uctx;

/* note data */
struct elf_prstatus prstatus;
struct user_desc user_desc;

struct {
	unsigned count;
	unsigned page_size; /* unit for file offset */
} note_file_header;

struct note_file_file {
	unsigned long start;
	unsigned long end;
	unsigned long file_offset;
	char filename[FILENAME_SIZE];
} note_file_files[256];

/* functions */

void error(char *msg) {
	write(2, msg, strlen(msg));
	write(2, "\n", 1);
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
		if (phdr.p_type == type)
			(*func)(f, &phdr);
	}
}

void process_note_file(FILE *f, long note_file_desc_offset) {
	long entry_offset, filename_offset;
	int i;

	read_at(f, note_file_desc_offset, &note_file_header,
			sizeof(note_file_header), 1);
	entry_offset = note_file_desc_offset + sizeof(note_file_header);
	filename_offset = entry_offset
		+ note_file_header.count * NOTE_FILE_ENTRY_SIZE ;

	for (i = 0; i < note_file_header.count; ++i) {
		read_at(f, entry_offset, &note_file_files[i],
				NOTE_FILE_ENTRY_SIZE, 1);
		read_at(f, filename_offset, note_file_files[i].filename,
				1, FILENAME_SIZE);
		note_file_files[i].filename[FILENAME_SIZE - 1] = '\0';

		entry_offset += NOTE_FILE_ENTRY_SIZE;
		filename_offset += strlen(note_file_files[i].filename) + 1;
	}
}

void process_segment_note(FILE *f, Elf32_Phdr *phdr) {
	long desc_offset, offset;
	struct {
		int name_size;
		int desc_size;
		int type;
	} note_header;

	offset = phdr->p_offset;
	while (offset < phdr->p_offset + phdr->p_filesz) {
		read_at(f, offset, &note_header, sizeof(note_header), 1);

		// offset at current note
		offset += sizeof(note_header);
		// offset at name
		offset += note_header.name_size;
		offset = ALIGN4(offset);
		// offset at desc
		desc_offset = offset;
		offset += note_header.desc_size;
		offset = ALIGN4(offset);
		// offset at next note

		switch (note_header.type) {
		case NT_PRSTATUS:
			read_at(f, desc_offset, &prstatus,
				sizeof(prstatus), 1);
			break;
		case NT_FILE:
			process_note_file(f, desc_offset);
			break;
		case NT_386_TLS:
			read_at(f, desc_offset, &user_desc,
				sizeof(user_desc), 1);
			break;
		}
	}
}

void process_segment_load(FILE *f, Elf32_Phdr *phdr) {
	int i;
	struct note_file_file *file = NULL;

	/* check if there is a  backing file */
	for (i = 0; i < note_file_header.count; ++i)
		if (phdr->p_vaddr == note_file_files[i].start)
			file = &note_file_files[i];

	// TODO

	printf("Load segment\n");
	if (file != NULL)
		printf("%s\n", file->filename);
	printf("p_offset\t%d\n", phdr->p_offset);
	printf("p_vaddr\t0x%x\n", phdr->p_vaddr);
	printf("p_filesz\t%d\n", phdr->p_filesz);
	printf("p_memsz\t%d\n", phdr->p_memsz);
	printf("p_flags\t%d\n", phdr->p_flags);
	printf("p_align\t%d\n", phdr->p_align);
	printf("\n");
}

void do_raise(char *filename) {
	FILE *f;

	/* open file */
	f = fopen(filename, "r");
	if (f == NULL) error("Failed to open the file");

	/* verify file, extract notes */
	verify_header(f);
	for_each_segment(f, PT_NOTE, process_segment_note);

	/* load segments */
	for_each_segment(f, PT_LOAD, process_segment_load);

	/* close file */
	fclose(f);

	// TODO

	/* tls */
	printf("TLS %u: 0x%x %d\n\n", user_desc.entry_number,
		user_desc.base_addr, user_desc.limit);

	/* prstatus (see user_regs struct) */
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
}


int main(int argc, char *argv[]) {
	if (argc != 2) error("Supply exactly one argument (core file name)");

	if (getcontext(&uctx) == -1)
		error("getcontext failed");
	uctx.uc_stack.ss_sp = stack;
	uctx.uc_stack.ss_size = sizeof(stack);
	uctx.uc_link = NULL;
	makecontext(&uctx, (void (*)(void)) do_raise, 1, argv[1]);
	setcontext(&uctx);
}
