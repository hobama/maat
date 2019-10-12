CC = gcc
CXX = g++

OUTDIR = ./bin
LIB_FILE = libmaat.so
BINDINGS_FILE = maat.so

## Basic default flags 
CFLAGS ?=
CXXFLAGS ?=
CXXFLAGS ?=
LDFLAGS ?=
LDLIBS ?=
LDLIBS += -lcapstone

## Flags for LIEF backend
LIEF ?= 0
ifeq ($(LIEF), 1)
    # USE CXX11 ABI = 0 if we use LIEF (otherwise linking problems :( with std::string and basic_string<> )
	CXXFLAGS += -DLIEF_BACKEND=1 -D_GLIBCXX_USE_CXX11_ABI=0
	CXXFLAGS += -DHAS_LOADER_BACKEND=1
	LDLIBS += -lLIEF
endif

## Flags for Z3 backend
Z3 ?= 0
ifeq ($(Z3), 1)
	CXXFLAGS += -DZ3_BACKEND=1
	CXXFLAGS += -DHAS_SOLVER_BACKEND=1
	LDLIBS += -lz3
endif

## Bindings
BINDINGS ?= 1
ifeq ($(BINDINGS), 1)
	CXXFLAGS += `python3-config --cflags` -DPYTHON_BINDINGS -Ibindings/python
	BINDINGS_DIR = ./bindings/python
	BINDINGS_SRCS = $(wildcard $(BINDINGS_DIR)/*.cpp)
	BINDINGS_OBJS = $(BINDINGS_SRCS:.cpp=.o)
	BINDINGS_RULE = bindings
	LDLIBS += `python3-config --libs`
else
	BINDINGS_RULE = 
endif

## Flags for debug mode
DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CFLAGS += -g -O0
	CXXFLAGS += -g -O0
	LDFLAGS += -g
else
	CFLAGS += -O2
	CXXFLAGS += -O2
endif

## Final C++ flags
CXXFLAGS += -std=c++11 -fPIC -I src/include -I dependencies/murmur3 -Wno-write-strings -Wno-sign-compare -Wno-reorder

# Source files
SRCDIR=./src
SRCS=$(SRCDIR)/expression/expression.cpp $(SRCDIR)/expression/simplification.cpp $(SRCDIR)/expression/constraint.cpp
SRCS+=$(wildcard $(SRCDIR)/ir/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/engines/*.cpp)
SRCS+=$(SRCDIR)/arch/arch.cpp $(SRCDIR)/arch/disassembler.cpp $(SRCDIR)/arch/archX86.cpp
SRCS+=$(SRCDIR)/solver/z3_solver.cpp
SRCS+=$(SRCDIR)/loader/lief_loader.cpp
SRCS+=$(wildcard $(SRCDIR)/env/*.cpp)
SRCS+=$(wildcard $(SRCDIR)/utils/*.cpp)
OBJS=$(SRCS:.cpp=.o)

TESTDIR = ./tests/unit-tests
TESTSRCS = $(wildcard $(TESTDIR)/*.cpp)
TESTOBJS = $(TESTSRCS:.cpp=.o)

ADVTESTDIR = ./tests/advanced-tests
ADVTESTSRCS = $(wildcard $(ADVTESTDIR)/*.cpp)
ADVTESTOBJS = $(ADVTESTSRCS:.cpp=.o)

DEPDIR = ./dependencies
DEPSRCS = $(DEPDIR)/murmur3/murmur3.c 
DEPOBJS = $(DEPSRCS:.c=.o)

INCLUDEDIR = ./src/include

# Compile lib and tests 
all: unit-tests adv-tests lib $(BINDINGS_RULE)

# unit tests 
unit-tests: $(TESTOBJS) $(OBJS) $(DEPOBJS) $(BINDINGS_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/unit-tests $(TESTOBJS) $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS)  $(LDLIBS) 

# advanced tests
adv-tests: $(ADVTESTOBJS) $(OBJS) $(DEPOBJS) $(BINDINGS_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/advanced-tests $(ADVTESTOBJS) $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# libmaat
lib: $(OBJS) $(DEPOBJS) $(BINDINGS_OBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/libmaat.so -shared $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# bindings
bindings: $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $(OUTDIR)/maat.so -shared $(BINDINGS_OBJS) $(OBJS) $(DEPOBJS) $(LDLIBS)

# generic 
%.o : %.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

%.o : %.c
	$(CC) $(CFLAGS) $(LDFLAGS) -c $< -o $@ $(LDLIBS)

# Installation (assuming Linux system) 
# If prefix not set, set default
ifeq ($(PREFIX),)
    PREFIX = /usr
endif

# Check if lib and binding files exist
ifneq (,$(wildcard ./bin/libmaat.so))
    INSTALL_LIB_RULE=install_lib
else
	INSTALL_LIB_RULE=
endif
ifneq (,$(wildcard ./bin/maat.so)) 
    INSTALL_BINDINGS_RULE=install_bindings
    PYTHONDIR=$(shell python3 -m site --user-site)/
else
	INSTALL_BINDINGS_RULE=
endif

# make install command
install: $(INSTALL_LIB_RULE) $(INSTALL_BINDINGS_RULE)
	@echo "Maat was successfully installed."

install_lib:
	install -d $(DESTDIR)$(PREFIX)/lib/
	install -D $(OUTDIR)/libmaat.so $(DESTDIR)$(PREFIX)/lib/
	install -d $(DESTDIR)$(PREFIX)/include/
	install -D $(INCLUDEDIR)/maat.hpp $(DESTDIR)$(PREFIX)/include/

install_bindings:
	install -d $(PYTHONDIR)
	install -D $(OUTDIR)/maat.so $(PYTHONDIR)

# make test command
test:
	$(OUTDIR)/unit-tests
	$(OUTDIR)/advanced-tests

# cleaning 
cleanall: clean

clean:
	rm -f $(OBJS)
	rm -f $(TESTOBJS)
	rm -f $(ADVTESTOBJS)
	rm -f $(DEPOBJS)
	rm -f $(BINDINGS_OBJS)
	rm -f `find . -type f -name "*.gch"`
	rm -f $(OUTDIR)/*

