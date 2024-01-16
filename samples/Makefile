.PHONY: clean

TARGETS := client server

CC := gcc

RELEASE := -DNDEBUG
LDFLAGS := -Wl,-Bdynamic -lrdmacm -libverbs -lpthread 
CFLAGS  += -Wall -g -I../include $(RELEASE)

all: clean $(TARGETS)

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

client: client.o
	$(CC) -o $@ $^ $(CFLAGS) -L../libs -Wl,-Bstatic -lsnowrdma -Wl,-rpath=../libs $(LDFLAGS)

server: server.o
	$(CC) -o $@ $^ $(CFLAGS) -L../libs -Wl,-Bstatic -lsnowrdma -Wl,-rpath=../libs $(LDFLAGS)

clean:
	rm -rf $(TARGETS) *.o

