# Makefile for vm selftests

CFLAGS = -Wall
BINARIES = hugepage-mmap hugepage-shm map_hugetlb thuge-gen hugetlbfstest
BINARIES += transhuge-stress
BINARIES += userfaultfd

all: $(BINARIES)
%: %.c
	$(CC) $(CFLAGS) -o $@ $^ -lrt
userfaultfd: userfaultfd.c
	$(CC) $(CFLAGS) -O2 -o $@ $^ -lpthread

TEST_PROGS := run_vmtests
TEST_FILES := $(BINARIES)

include ../lib.mk

clean:
	$(RM) $(BINARIES)
