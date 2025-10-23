.PHONY: all clean

all:
	$(MAKE) -C selftests
	./selftests/selftest

clean:
	$(MAKE) -C selftests clean
