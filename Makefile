all:
	$(MAKE) -C selftests
	./selftests/selftest

.PHONY: all
