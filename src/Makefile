EXEC = zdbfs
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

CFLAGS += -g -std=gnu99 -O0 -W -Wall -Wextra -Wno-implicit-fallthrough -I/usr/include/fuse3
LDFLAGS += -Wl,-Bstatic -lunwind -Wl,-Bdynamic -rdynamic -lfuse3 -lpthread -lhiredis -ldl -llzma

all: $(EXEC)

profile: CFLAGS += -pg
profile: LDFLAGS += -pg
profile: all

release: CFLAGS += -DRELEASE -O2 -march=native
release: clean $(EXEC)

production: CFLAGS += -DRELEASE -O2
production: LDFLAGS = -rdynamic -static -lhiredis -lunwind -lfuse3 -lpthread -ldl -llzma
production: all

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) *.o

mrproper: clean
	$(RM) $(EXEC)

