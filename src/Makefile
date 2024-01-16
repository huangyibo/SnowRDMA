.PHONY: clean

CC := gcc
AR := ar

RELEASE := -DNDEBUG
LDFLAGS := -Wl,-Bdynamic -lrdmacm -libverbs -lpthread 
CFLAGS +=  -Wall -g -I. $(RELEASE)

RDMA_OBJS = common.o rdma_helpers.o rdma.o
RDMA_SRC := common.c rdma_helpers.c rdma.c
HEADER_SRC := common.h rdma_helpers.h rdma.h
RELEASE_HEADER := rdma.h

STATIC_LIB = libsnowrdma.a
DYNAMIC_LIB = libsnowrdma.so

all: clean $(STATIC_LIB) $(DYNAMIC_LIB)
	@if [ ! -d "../libs" ]; then mkdir libs; fi
	@if [ ! -d "../include" ]; then mkdir include; fi
	cp $(RELEASE_HEADER) ../include/

%.o: %.c %.h
	$(CC) $(CFLAGS) -c $< -o $@

$(STATIC_LIB): $(RDMA_OBJS) $(HEADER_SRC)
	$(AR) -cvq $@ $(RDMA_OBJS)
	mv $(STATIC_LIB) ../libs/

$(DYNAMIC_LIB): $(RDMA_SRC) $(HEADER_SRC)
	$(CC) -fPIC -shared $(CFLAGS) $(RDMA_SRC) -o $@ $(LDFLAGS)
	mv $(DYNAMIC_LIB) ../libs/

clean:
	rm -rf *.o $(RDMA_OBJS) $(STATIC_LIB) $(DYNAMIC_LIB)

install:
	cp ../libs/* /usr/local/lib 
	cp ../include/* /usr/local/include
