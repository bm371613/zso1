all: raise

raise: src/raise.c
	gcc src/raise.c -o raise -m32 -static \
		-Xlinker -Tbss=0x1000400 \
		-Xlinker -Tdata=0x2000400 \
		-Xlinker -Ttext=0x3000400

clean:
	rm -f raise

.PHONY: clean

