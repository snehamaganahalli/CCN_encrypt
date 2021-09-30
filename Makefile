CFLAGS = -O2 -Wall -fPIC
SO_LINKS = -lm -lcrypto

LIB = libfpe.a libfpe.so
MAIN_SRC = main.c
MAIN_EXE = main
OBJS = src/ff1.o  src/fpe_util.o

all: $(LIB) $(MAIN_EXE)

libfpe.a: $(OBJS)
	ar rcs $@ $(OBJS)

libfpe.so: $(OBJS)
	cc -shared -fPIC -Wl,-soname,libfpe.so $(OBJS) $(SO_LINKS) -o $@

.PHONY = all clean

src/ff1.o: src/ff1.c
	cc $(CFLAGS) -c src/ff1.c -o $@

src/fpe_util.o: src/fpe_util.c
	cc $(CFLAGS) -c src/fpe_util.c -o $@

$(MAIN_EXE): $(MAIN_SRC) $(LIB)
	gcc -g -Wl,-rpath=\$$ORIGIN $(MAIN_SRC) -L. -lfpe -Isrc -O2 -o $@

clean:
	rm $(OBJS)

