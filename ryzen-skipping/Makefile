FLAGS = -falign-functions=64 --no-pie -static -g -O0

SRCS = $(wildcard *.c)

PROGS = $(patsubst %.c,%,$(SRCS))
ALL_PROGS = $(PROGS)

FILENAME_ALL_PROGS = $(notdir $(ALL_PROGS))
DUMPS = $(addprefix dump_, $(FILENAME_ALL_PROGS))

all: $(PROGS)

dump: $(DUMPS)

%: %.c $(HEADS)
	gcc $(FLAGS) -o $@ $< $(LIBS)

dump_%: %
	objdump -d $< > $@

readme: readme.md
	pandoc readme.md --css table.css > readme.html

clean:
	rm -f $(ALL_PROGS) $(DUMPS)
