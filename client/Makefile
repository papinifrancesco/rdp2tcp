BIN=rdp2tcp
CC=gcc
CFLAGS=-Wall -g -I../common
#CFLAGS=-Wall -g -I../common -DDEBUG
LDFLAGS=
OBJS=main.o netsock.o tunnel.o channel.o commands.o controller.o socks5.o \
	  ../common/nethelper.o \
	  ../common/netaddr.o \
	  ../common/iobuf.o \
	  ../common/print.o \
	  ../common/msgparser.o

# clean first: the POSIX and mingw builds share .o names in this directory,
# so a stale object from the other toolchain would otherwise be linked in
all: clean clean_common $(BIN)

clean_common:
	$(MAKE) -C ../common clean

$(BIN): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS) 

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f $(OBJS) $(BIN)
