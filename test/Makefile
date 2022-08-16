# common rules for testing libmallochooks

# we always build
# malloc.o
# exe.o
# dso.o
# exe
# libdl.so
#
# ... but the configuration varies

-include $(dir $(lastword $(MAKEFILE_LIST)))/testconfig.mk

CFLAGS += -fPIC -g
LDFLAGS :=
LDFLAGS += -L.

# FIXME HACK HACK HACK: just use the sysv hash table, until
# elftin's sym2dyn can regenerate the GNU one as well
LDFLAGS += -Wl,--hash-style=sysv

case := $(notdir $(shell pwd))
ifeq ($(case),test)
.PHONY: default
default:
	for d in malloc-in-*; do $(MAKE) -C $$d -f ../Makefile || break; done
else

.PHONY: default run
default: exe libdso.so run
run:
	./exe

malloc.c: dlmalloc.c
	cp $< $@

malloc.o: CFLAGS += -DHAVE_MORECORE=0

libdso.so: lib.o

testdir := $(dir $(realpath $(lastword $(MAKEFILE_LIST))))
$(info testdir is $(testdir))

vpath %.c $(testdir)
vpath %.c $(testdir)/../contrib

ifeq ($(case),malloc-in-exe)
exe: malloc.o mallochooks.o
MALLOCHOOKS_TARGET := exe
MALLOCHOOKS_LIST := terminal-direct
else
ifeq ($(case),malloc-in-dso)
libdso.so: malloc.o mallochooks.o
MALLOCHOOKS_TARGET := libdso.so
MALLOCHOOKS_LIST := terminal-indirect-dlsym
else
ifeq ($(case),malloc-in-libc)
# do nothing??! no, we preload our hooks
default: preload.so
MALLOCHOOKS_TARGET := preload.so
MALLOCHOOKS_LIST := terminal-indirect-dlsym
preload.so: mallochooks.o
	$(CC) -shared -o $@ $+ $(LDFLAGS) $(LDLIBS)
else
$(error Unrecognised case: $(case))
endif
endif
endif

exe: LDLIBS += -Wl,-rpath,$(shell pwd) -ldso
exe: main.o
exe: libdso.so
libdso.so: LDFLAGS := $(LDFLAGS) # IMPORTANT! prevent exe-specific LDFLAGS from propagating to prereqs
libdso.so:
	$(CC) -o $@ -shared $(filter %.o,$+) $(LDFLAGS) $(LDLIBS)
# need --export-dynamic to avoid an exe-specific malloc
exe: LDFLAGS := $(LDFLAGS) -Wl,--export-dynamic
# use -ldl just so we can dlsym (etc) in gdb
exe: LDLIBS += -ldl
exe:
	$(CC) -o $@ $(filter %.o,$+) $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) -c -o $@ $+ $(CFLAGS) $(CPPFLAGS)

.PHONY: clean
clean::
	rm -f exe libdso.so *.o *.i

# include rules for building mallochooks.mk
include $(testdir)/../src/rules.mk
# include the built mallochooks.mk --this has rules for linking the TARGET
# (maybe rules.mk could do this, but we want to separate out
# a nice simple makefile specifying the hooking, so that
# our ld plugin can emulate it)
include mallochooks.mk

endif
