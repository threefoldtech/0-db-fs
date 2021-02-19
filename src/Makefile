EXEC = zdbfs
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)

CFLAGS += -g -std=gnu99 -O0 -W -Wall -Wextra -Wno-implicit-fallthrough -I/usr/include/fuse3
LDFLAGS += -rdynamic -lfuse3 -lpthread -lhiredis

all: $(EXEC)

release: CFLAGS += -DRELEASE -O2 -march=native
release: clean $(EXEC)

production: CFLAGS += -DRELEASE -O2
production: LDFLAGS = -Wl,-Bstatic -lhiredis -Wl,-Bdynamic -rdynamic -lfuse3 -lpthread -ldl
production: all

$(EXEC): $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	$(RM) *.o

mrproper: clean
	$(RM) $(EXEC)
