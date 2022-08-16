# These makerules are design to 'drop in' to the build process
# for some ELF DSO (incl. executable) that, when built, will define
# a global, non-hidden, dynamic-exported 'malloc' symbol, along with
# some or all of the other calls in the family (calloc, free, realloc,
# memalign, posix_memalign, and possibly malloc_usable_size).
#
# By including these makerules, hooks are generated and linked in to the
# target binary, *replacing* the malloc entry points that would (possibly)
# otherwise be present in that binary. The inserted hooks may (but need not)
# call back into those entry points to do their actual malloc operations.
#
# Normally the target DSO defines an implementation of malloc proper. But
# it might also just be a preload library whos job is to delegate to a 
# malloc found elsewhere. These rules cover both cases. In the case
# of a preload library, these rules (and the hook code) are all you need;
# the target DSO need not have an existing implementation of malloc. By 
# supplying the right "termination" you can instead arrange that the hooks
# finish by delegating to the global malloc, as found in some other DSO.
#
# Requirements on the include context of this makefile:
# - MALLOCHOOKS_TARGET must be set to the binary to contain hooks
# - MALLOCHOOKS_LIST must be set to a list of hook source files (without '.c'),
#   of which the final is a 'terminal' hook that calls a real malloc.
# - the including file must also include mallochooks.mk -- that is a file that
#   *these* makerules express how to generate
# - the including file must be invokable by 'make -f' to build $(MALLOCHOOKS_TARGET)
# - if the including file defines 'clean', it must be a double-colon rule, since
#   we add our own clean logic.

ifeq ($(MALLOCHOOKS_TARGET),)
$(error Must set MALLOCHOOKS_TARGET to the executable into which hooks are to be linked)
endif

ifeq ($(MALLOCHOOKS_LIST),)
$(error Must set MALLOCHOOKS_LIST to a list of hook source files (without '.c'))
endif
$(info MALLOCHOOKS_LIST is $(MALLOCHOOKS_LIST))

# The main idea is to add to the link a __wrap_malloc entry point
# that is then renamed to 'malloc' using extra makerules.
# We do the renaming in a clever way so that the original malloc (if present)
# remains present and accessible.
#
# Exactly what the __wrap_malloc entry point does is user-defined, but
# it take the form of running a series of hooks, in order, ended by a
# 'terminal' hook-like stage that calls a real malloc (perhaps the malloc
# that was alrady being linked in to the binary, and is now renamed but
# remains accessible; or perhaps some other malloc, in the case of a preload
# library that does not define a malloc itself).
#
# The makerules here must do several things.
#
# - add the __wrap_ entry points to the link
# - apply --wrap when linking the DSO, to divert DSO-internal references
#   that would otherwise be bound locally within the DSO.
#       -- OR actually do our extended wrapping that unbinds etc.
# - do symbol renaming after linking the DSO, to divert DSO-*external* references
#   that want to bind to 'malloc' and therefore should hit our new entry point.
#       -- OR use muldefs-based wrapping so that this is unnecessary
#       -- given the nastiness of sym2dyn, it seems a better option, and
#          saves us from having to manually fix up the GNU hash table
#          (and the dynstr issue), although those would be good to have.
#
# FIXME: what if it would be bound to an external, but now gets bound to our __wrap_malloc?
# If it's a target, it has a global non-hidden dyn-exported 'malloc', so I think we're
# all right. If it was binding to that malloc, it now binds to __wrap_malloc, but
# if it wasn't...
#
# Their terminal hooks may be either terminal-indirect-dlsym or (with
# pre-aliasing) terminal-direct. Pre-aliasing means 
#
# Another library DSO may be a target if it's to be used as a preload library.
# In that case it must use the terminal-indirect-dlsym hooks, and its
# front end has no symbol prefix. In many ways this is simpler.
# We don't care whether the library DSO is intended to be preloaded or not.
#
# toolsub idea: maybe we want a --predefsym option, defining symbols that
# can be referenced by --defsym. Predef's RHSes see the symbol space *before*
# defsym. What's our interaction between toolsub and the linker plugin?
# I think we just wanted the linker toolsub to be a friendly scaffold for
# tooling implemented as a linker plugin. Unclear this is the right/only thing.
#
# YES, predefsym is a good idea. I think allocscompilerwrapper.py's use
# of a two-stage link (*.linked.o) is to get around this. That is a horrible
# mess that we want to avoid.

mallochooks_mk := #
LD ?= ld
LD_R_FLAGS :=
mallochooks.o:
	$(LD) -r -o $@ $+ $(LD_R_FLAGS)
mallochooks.mk:
	echo '$(mallochooks_mk)' > "$@" || (rm -f "$@"; false)

this_makefile := $(lastword $(MAKEFILE_LIST))
srcdir := $(dir $(this_makefile))
vpath %.c $(srcdir)

# our source files need our includes
objs := $(patsubst %.c,%.o,$(shell cd $(srcdir) && ls *.c))
$(objs): CFLAGS += -I$(srcdir)/../include

# we depend on our hook .o files
mallochooks.o: $(patsubst %,%.o,$(MALLOCHOOKS_LIST))

# we always build with user2hook.o
mallochooks.o: user2hook.o
# user2hook needs the first hook -- in extremis first can be terminal
first_hook_prefix := $(if $(filter terminal-%,$(word 1,$(MALLOCHOOKS_LIST))), \
 __terminal_hook_, \
 __hook1_ \
)
user2hook.o: CFLAGS += -D'HOOK_PREFIX(x)=$(first_hook_prefix)\#\#x' \
  -D'MALLOC_PREFIX(x)=__wrap_\#\#x'
# FIXME: preload hooks don't need the __wrap_ prefix
# but maybe it doesn't matter? We are going to redef '__wrap_malloc' to 'malloc'.
# Similarly, we are adding --wrap to the link options even in the
# preload case, but that's fine because it should not directly
# reference the real malloc as termination. It may reference it to
# call malloc, but then it should get us. So all good?
mallochooks_mk := $(MALLOCHOOKS_TARGET): LDFLAGS += \
 -Wl,--wrap,malloc \
 -Wl,--wrap,calloc \
 -Wl,--wrap,realloc \
 -Wl,--wrap,free \
 -Wl,--wrap,memalign \
 -Wl,--wrap,posix_memalign

clean::
	rm -f mallochooks.mk

# now the terminal case
ifneq ($(words $(MALLOCHOOKS_LIST)),1)
$(word $(words $(MALLOCHOOKS_LIST)) $(MALLOCHOOKS_LIST)).o: CFLAGS += \
 -D__next_hook_malloc=__terminal_hook_malloc \
 -D__next_hook_realloc=__terminal_hook_realloc \
 -D__next_hook_free=__terminal_hook_free \
 -D__next_hook_memalign=__terminal_hook_memalign
endif

# FIXME: move this to an example (using librunt/relf.h)
terminal-indirect-dlsym.o: CFLAGS += \
  -Ddlsym_nomalloc=fake_dlsym -include assert.h -include stdlib.h -include link.h -I$(LIBRUNT_INCLUDE) -include relf.h

# now the cases in the middle
# for each source file in the list, except for the last one,
# define its next_hook to be the prefix
define set_cflags_for_nonterminal_hooks
$(word $(1) $(MALLOCHOOKS_LIST)).o: CFLAGS += \
 -D__next_hook_malloc=__hook$(shell expr $(1) + 1)_malloc \
 -D__next_hook_realloc=__hook$(shell expr $(1) + 1)_realloc \
 -D__next_hook_free=__hook$(shell expr $(1) + 1)_free \
 -D__next_hook_memalign=__hook$(shell expr $(1) + 1)_memalign
endef

# our hook indices are 1-based
# if we have ... words in the hooks list, the foreach below iterates over the list ...
#             1                           []   # no terminal case (handled by first_hook_prefix above)
#             2                           []   # + terminal case
#             3                           [1]  # + terminal case
#             4                           [1,2]# + terminal case
# always defining __next_hook_XXX=__hookN+1_XXX
#    for each N in the list
#    *in hook object N*
$(foreach n,$(shell seq 1 $(shell expr $(words $(MALLOCHOOKS_LIST)) - 3)),\
$(call set_cflags_for_nonterminal_hooks,$(n)))

mallochooks.o: $(TERMINAL_HOOKS)

ifeq ($(NO_TARGET_OVERRIDE),)
# always make the target the including Makefile's way
SYM2DYN ?= sym2dyn
OBJCOPY ?= objcopy
$(info HACK rules for building $(MALLOCHOOKS_TARGET))
$(MALLOCHOOKS_TARGET):
# override in case it's using a built-in rule
# ...
# now define our rule -- we will get re-included but excluding this section
$(MALLOCHOOKS_TARGET):
	$(MAKE) NO_TARGET_OVERRIDE=1 -f $(firstword $(MAKEFILE_LIST)) $@
	( \
	$(OBJCOPY) `for s in malloc calloc realloc free memalign posix_memalign; do echo --redefine-sym "$$s"=_"$$s"; done` $@ && \
	$(SYM2DYN) $@ && \
	$(OBJCOPY) `for s in malloc calloc realloc free memalign posix_memalign; do echo --redefine-sym __wrap_"$$s"="$$s"; done` $@ && \
	$(SYM2DYN) $@ && \
	true ) || (rm -f $@; false)
endif

# Our hooks object consists of
# a userapi object,
# one or more hooks objects,
# and a terminal hooks object.
#
# For preload, the client simply ensures the userapi object
# has no prefix, and uses the dlsym-based terminal hooks.
# It doesn't affect how we create or embed the hooks.
#
# What if the target object already includes things
# with names like 'malloc', i.e. the same names we want
# to define in the userapi object? This is
# the case when we're hooking a malloc defined in the exe.
# We need to rename things so that our userapi entry path
# is now the 'malloc' (et al)
# and the original malloc is called by the terminal hooks.
# The main problem is putting a symbol name on the original
# malloc that won't get clobbered... 'malloc' is no good!

# In allocscompilerwrapper.py we had to resort to a two-
# stage link for this. The second stage links in the userapi
# malloc, defsym'd from __wrap___real_malloc. By wrapping
# __real_malloc we divert the intra-DSO references coming
# from the caller-side hooks, that are calling __real_malloc,
# and by defsymming it as 'malloc' we are ready for the out-of-
# -DSO references. (I suspect the defsymming is enough for the
# caller-side cases too.)

# Using -z muldefs for wrapping doesn't help: we are back to
# having no way to bind to the 'real' original malloc. Normally
# we pre-alias in the .o files but we can't do that here.
#
# HMM. So can we write the additional makerules for
# %.linked.o? E.g. a log file of the original ld command?
# We could override CC  but not all binaries are built
# with CC.
# We could use toolsub to create + insert a ld wrapper.
# This seems reasonable although it is a bit indirect.
# We would have to add LDFLAGS += -wrapper.
# The wrapper could do a muldefs-style pre-aliasing on the
# input .o files
#
# Another idea: do the build adding -Wl,-Map=..., then parse the
# link map and use objcopy to define the __real_ aliases post-hoc.
# using objcopy --add-symbol .text+offset.
# (It would be nice if ld --defsym supported this syntax, but
# it doesn't and it's unclear which .text we'd be referencing.)
# Does this work? No because it relies on turning an
# undefined symbol into a defined one, and objcopy does not
# support this (it does not divert relocation records).
# Also, since objcopy is a separate step, we only have the
# rules for building a derivative object, not the original
# target object, breaking our intended drop-in{clude} design.
#
# Is there a way to introspect on the rules for building a
# given target? What we want to say is something like
# "define a new recipe for target, that is like the old
# recipe except additionally...". I don't think there is
# such a way. (Would be another kind of interposition!)
# Perhaps one way is creative use of recursive make?
# Although we are included, we can perhaps craft a recursive
# make call where the include doesn't happen?
# That would let us create the target as was originally
# intended, then do the objcopy.
#
# Instead of building with UND and rebinding later, we have
# to build with a reference to the wrong-named symbols (say
# '__wrap_malloc' instead of malloc) and wrong-named definition
# ('malloc' instead of '__real_malloc' or some other prefix),
# then fix it up later. Whether our fixed-up version gets build
# with the actual target's name or another name is for our caller.

# Can we mess with 'make', e.g. have the 'exe' rule actually
# output 'exe.o' (perhaps disguised as 'exe'),
# then use a phony target that always runs
# and that fixes up the .exe.o into .exe,
# using order-only prerequisites to ensure it runs last?
# Order-only prerequisites don't help. But we could do:
#
# .PHONY: fixup-pass
# fixup-pass:: $(MALLOCHOOKS_TARGET)
#
# HMM. So this gets us something like the two-stage link
# in allocscompilerwrapper.py. What does the fixup pass
# have to do?
#
# Problem with this is that the fixup pass won't run
# unless our phony target is triggered somehow.
# If we are just doing 'make <target>' then it won't run
# because it'd mean circular dependencies: fixup depends on
# the output so we can't make the output depend on fixup.
#
# Can we use recursive make here? Perhaps. Our makefile
# has two forks: one where we override the original rule
# for the exe and one where we don't. In the one where we don't,
# we add -Wl,-r to create the .linked.o. We can even write a
# rule that copies from the original exe name to .
# In the other one, we cancel the caller-provided rule.
# 
# Problem: this will break some uses of 'make' because not all
# makefiles are intended to be run with 'make -f'. We would be
# guessing that we can re-enter the makefile that included us,
# but that is not necessarily the case.
#
# I think what we need is:
#
# linking --wrap, or an equivalent using muldefs
# ... we don't use muldefs because it requires a pre-pass
#     to add aliases to the symtab of *input* objects
# a separate pass that does 'DSO-wrap' i.e.
# ... instead of __wrap_X and X, want X and __real_X
#    -- we *can* do this with objcopy except that it doesn't
#       apply changes to the dynsym, so write a tool that does this
# our unbind-alike trick using abs2und covers cases where def and ref are
#    in the same input object. We could instead use the
#    muldefs approach, which handles this gracefully at the
#    expense of requiring a different kind of pre-pass.
# If the user requests it, try the hacky reenter-and-fixup
#    approach to the makefile; otherwise just
#    skip the 'DSO-wrap' stage
#
# The take-home is that hooking into makefiles is hard because
# there's no way to add extra stages/commands to a recipe
# (making a transparent fixup pass difficult).
# We can add prerequisites/inputs but not remove them
# (making a per-object pre-pass difficult, cf. if we could substitute those objects)
# and have limited control of their order in $+
# (making muldefs tricky)

ifeq ($(TERMINAL_HOOKS),)
# guess the terminal hooks from the filename, and warn
ifeq ($(MALLOCHOOKS_TARGET),PRELOAD)
# unusual case: the malloc is not contained in the target binary
TERMINAL_HOOKS := terminal-indirect-dlsym.o
else
ifeq ($(suffix $(MALLOCHOOKS_TARGET)),.so)
TERMINAL_HOOKS := terminal-direct.o
else
ifeq ($(suffix $(MALLOCHOOKS_TARGET)),)
# It's an exe, so our terminal hooks are wrapdl.
# wrapdl is necessary for two reasons:
# - ld --wrap can only possibly catch intra-DSO references,
#   which isn't enough, so instead our wrapper really needs
#   to take the malloc's real name. That means we have to rename
#   the 'real' malloc to something else. But if we do that,
#   why can't our terminal hooks just use that to bind to the real malloc?
#   E.g. just direct-call __def_malloc or __real_malloc or _malloc.
#   __real_malloc is a problem because we already wrap
#   'malloc', so we can't bind to '__real_malloc':
#   it gets diverted to plain 'malloc', in return for 
#   diverting calls to 'malloc' to our '__wrap_malloc'.
#   But I guess direct-calling '__def_malloc' would work?
#   Or just '_malloc'. Let's try it.

# BUT we want 

#   We create these aliases in allocscompilerwrapper.py too.
#
#
# - we might be trying to wrap the wrappers,
#   and that breaks because... __real___real_ again?
endif
endif
endif
endif

# for all of the hook objects we've been asked for,
# include them in the link, and define __next_hook_*,
# finally using the terminal hooks
#$(foreach h,

