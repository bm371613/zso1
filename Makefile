all: raise

raise: raise.o set_registers.o
	gcc -m32 -static raise.o set_registers.o -o raise \
		-Xlinker -Tbss=0x1000400 \
		-Xlinker -Tdata=0x2000400 \
		-Xlinker -Ttext=0x3000400 \
		-Xlinker -Ttext-segment=0x4000000

raise.o: src/raise.c
	gcc -m32 -c src/raise.c -o raise.o

set_registers.o: src/set_registers.s
	gcc -m32 -c -x assembler src/set_registers.s -o set_registers.o

clean:
	rm -f raise raise.o set_registers.o

.PHONY: clean

