.PHONY: all client client-mingw32 server-mingw32 clean

all: client

# Delegate to the sub-Makefiles, which track .c/.o dependencies themselves.
# (Phony targets so an existing binary never short-circuits the rebuild.)
client:
	$(MAKE) -C client

client-mingw32:
	$(MAKE) -C client -f Makefile.mingw32

server-mingw32:
	$(MAKE) -C server -f Makefile.mingw32

clean:
	$(MAKE) -C client clean
	$(MAKE) -C client -f Makefile.mingw32 clean
	$(MAKE) -C server -f Makefile.mingw32 clean
	$(MAKE) -C tools clean
