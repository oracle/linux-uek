noarg:
	$(MAKE) -C ../

TEST_PROGS := adi_test

all: $(TEST_PROGS)

$(TEST_PROGS): adi_test.c

include ../../lib.mk

clean:
	rm -f $(TEST_PROGS)
