.PHONY: all clean

all:
	$(MAKE) -C selftests selftest
	./selftests/selftest

clean:
	$(MAKE) -C selftests clean
