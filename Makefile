all: raise

raise: src/raise.c src/raise.x
	gcc -m32 -static -Tsrc/raise.x src/raise.c -o raise

clean:
	rm -f raise

.PHONY: clean

