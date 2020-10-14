DOT := $(shell command -v colorgcc 2> /dev/null)
ifndef DOT
   CC=gcc
else
   CC=colorgcc
endif

all: c_switch_open


c_switch_open: c_switch_open.c
	$(CC) -fpic -pie -fno-stack-protector -m64 -mcmodel=medium -g -o c_switch_open -O0 c_switch_open.c -T linker_c_switch_open.ld

clean:
	rm -rf c_switch_open

dump: all
	objdump -d c_switch_open > dump_c_switch_open

