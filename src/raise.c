#include <asm/ldt.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/procfs.h>
#include <sys/syscall.h>
#include <ucontext.h>

#define ALIGN4(value) (((value) + 3) & (~3) )
#define FILENAME_SIZE 256
#define NOTE_FILE_ENTRY_SIZE (3 * sizeof(unsigned long))

char filename[FILENAME_SIZE], stack[16384];
int fd;
Elf32_Ehdr hdr;

/* note data */
#define NOTE_FOUND_PRSTATUS 1
#define NOTE_FOUND_FILE 2
#define NOTE_FOUND_386_TLS 4
#define NOTE_FOUND_ALL_RELEVANT \
	(NOTE_FOUND_PRSTATUS | NOTE_FOUND_FILE | NOTE_FOUND_386_TLS)
int notes_found = 0;

struct elf_prstatus prstatus;
struct user_desc user_desc;

struct {
	unsigned count;
	unsigned page_size; /* unit for file offset */
} note_file_header;

struct note_file_file {
	unsigned long start;
	unsigned long end;
	unsigned long pgoff;
	char filename[FILENAME_SIZE];
} note_file_files[256];

/* assembly interface */
unsigned long eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, eflags;

void set_registers();

/* functions */
void error(char *msg) {
	write(2, msg, strlen(msg));
	write(2, "\n", 1);
	exit(1);
}

int read_at(long offset, void *ptr, size_t size) {
	int read_count;

	if (lseek(fd, offset, SEEK_SET) < 0)
		error("lseek");
	while (size > 0) {
		read_count = read(fd, ptr, size);
		if (read_count < 0)
			error("read");
		ptr += read_count;
		size -= read_count;
	}
}

void for_each_program_header(Elf32_Word type, void (*func)(Elf32_Phdr*)) {
	int i;
	Elf32_Phdr phdr;

	for (i = 0; i < hdr.e_phnum; ++i) {
		read_at(hdr.e_phoff + i * hdr.e_phentsize, &phdr,
				sizeof(Elf32_Phdr));
		if (phdr.p_type == type)
			(*func)(&phdr);
	}
}

void process_note_file(long note_file_desc_offset) {
	long entry_offset, filename_offset;
	int i;

	read_at(note_file_desc_offset, &note_file_header,
			sizeof(note_file_header));
	entry_offset = note_file_desc_offset + sizeof(note_file_header);
	filename_offset = entry_offset
		+ note_file_header.count * NOTE_FILE_ENTRY_SIZE ;

	for (i = 0; i < note_file_header.count; ++i) {
		read_at(entry_offset, &note_file_files[i],
				NOTE_FILE_ENTRY_SIZE);
		read_at(filename_offset, note_file_files[i].filename,
				FILENAME_SIZE);
		note_file_files[i].filename[FILENAME_SIZE - 1] = '\0';

		entry_offset += NOTE_FILE_ENTRY_SIZE;
		filename_offset += strlen(note_file_files[i].filename) + 1;
	}
}

void process_program_header_note(Elf32_Phdr *phdr) {
	long desc_offset, offset;
	struct {
		int name_size;
		int desc_size;
		int type;
	} note_header;

	offset = phdr->p_offset;
	while (offset < phdr->p_offset + phdr->p_filesz) {
		read_at(offset, &note_header, sizeof(note_header));

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
			if (notes_found & NOTE_FOUND_PRSTATUS)
				error("Multiple NT_PRSTATUS notes.");
			notes_found |= NOTE_FOUND_PRSTATUS;
			read_at(desc_offset, &prstatus, sizeof(prstatus));
			break;
		case NT_FILE:
			if (notes_found & NOTE_FOUND_FILE)
				error("Multiple NT_FILE notes.");
			notes_found |= NOTE_FOUND_FILE;
			process_note_file(desc_offset);
			break;
		case NT_386_TLS:
			if (notes_found & NOTE_FOUND_386_TLS)
				error("Multiple NT_386_TLS notes.");
			notes_found |= NOTE_FOUND_386_TLS;
			read_at(desc_offset, &user_desc, sizeof(user_desc));
			break;
		}
	}
}

void process_program_header_load(Elf32_Phdr *phdr) {
	int i, b_fd, prot;
	struct note_file_file *b_file = NULL;
	void *mem;

	/* check if there is a  backing file */
	for (i = 0; i < note_file_header.count; ++i)
		if (phdr->p_vaddr == note_file_files[i].start)
			b_file = &note_file_files[i];

	/* map memory */
	if (b_file == NULL) {
		mem = mmap((void*) phdr->p_vaddr, phdr->p_memsz, PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, 0, 0);
	} else {
		b_fd = open(b_file->filename, O_RDONLY);
		if (b_fd == -1)
			error("open mapped file");
		mem = mmap((void*) phdr->p_vaddr, phdr->p_memsz, PROT_WRITE,
				MAP_PRIVATE | MAP_FIXED,
				b_fd,
				b_file->pgoff * note_file_header.page_size);
		close(b_fd);
	}

	if (mem == MAP_FAILED)
		error("mmap");

	if (mem != (void*) phdr->p_vaddr)
		error("mmap at requested address");

	/* copy data */
	read_at(phdr->p_offset, mem, phdr->p_filesz);

	/* protect memory */
	prot = PROT_NONE;
	if (phdr->p_flags & PF_R)
		prot = prot | PROT_READ;
	if (phdr->p_flags & PF_W)
		prot = prot | PROT_WRITE;
	if (phdr->p_flags & PF_X)
		prot = prot | PROT_EXEC;
	if (mprotect(mem, phdr->p_memsz, prot) == -1)
		error("mprotect");
}

void do_raise() {
	/* unmap old stack */
	munmap((void*) 0x8000000, 0xc0000000 - 0x8000000);

	/* open file */
	fd = open(filename, O_RDONLY);
	if (fd < 0) error("Failed to open the file.");

	/* read and verify header */
	if (read_at(0, &hdr, sizeof(Elf32_Ehdr)) != sizeof(Elf32_Ehdr)
			|| hdr.e_ident[EI_MAG0] != ELFMAG0
			|| hdr.e_ident[EI_MAG1] != ELFMAG1
			|| hdr.e_ident[EI_MAG2] != ELFMAG2
			|| hdr.e_ident[EI_MAG3] != ELFMAG3)
		error("Not an ELF.");
	if (hdr.e_type != ET_CORE)
		error("Not a core ELF.");
	if (hdr.e_machine != EM_386)
		error("Bad machine.");
	if (hdr.e_version != EV_CURRENT)
		error("Bad version.");

	/* extract relevant info from notes */
	for_each_program_header(PT_NOTE, process_program_header_note);
	if ((notes_found & NOTE_FOUND_ALL_RELEVANT) != NOTE_FOUND_ALL_RELEVANT)
		error("Relevant notes missing.");

	/* set up memory */
	for_each_program_header(PT_LOAD, process_program_header_load);

	/* close file */
	close(fd);

	/* prepare registers */
	eax = prstatus.pr_reg[6];
	ebx = prstatus.pr_reg[0];
	ecx = prstatus.pr_reg[1];
	edx = prstatus.pr_reg[2];
	esi = prstatus.pr_reg[3];
	edi = prstatus.pr_reg[4];
	ebp = prstatus.pr_reg[5];
	esp = prstatus.pr_reg[15];
	eip = prstatus.pr_reg[12];
	eflags = prstatus.pr_reg[14];

	/* tls */
	if (syscall(SYS_set_thread_area, &user_desc) < 0)
		error("tls");

	/* set registers */
	set_registers();
	error("unreachable");
}


int main(int argc, char *argv[]) {
	ucontext_t uctx;

	if (argc != 2)
		error("Supply exactly one argument (core file name).");
	strcpy(filename, argv[1]);

	if (getcontext(&uctx) == -1)
		error("getcontext");
	uctx.uc_stack.ss_sp = stack;
	uctx.uc_stack.ss_size = sizeof(stack);
	uctx.uc_link = NULL;
	makecontext(&uctx, (void (*)(void)) do_raise, 0);
	setcontext(&uctx);
}
