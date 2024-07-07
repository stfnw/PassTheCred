.PHONY: all clean watch

PASS_THE_CRED_GIT_COMMIT := $(shell git rev-parse HEAD)

all: PassTheCred.exe

clean:
	rm -vf -- $(wildcard *.o *.exe *.dll)

watch:
	while true ; do \
		inotifywait -qr -e close_write *.c *.h ; \
		make all ; \
		echo ; echo ; echo ; echo ; \
	done

CC      := x86_64-w64-mingw32-gcc
CFLAGS  := -Wextra -Wall -Wpedantic -municode -DPASS_THE_CRED_GIT_COMMIT=\"$(PASS_THE_CRED_GIT_COMMIT)\"
LDFLAGS := $(CFLAGS)

LDLIBS += -lntdll
LDLIBS += -lbcrypt
LDLIBS += -lsecur32

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

%.exe: %.o
	$(CC) $(LDFLAGS) -o $@ $< $(LDLIBS)
%.dll: %.o
	$(CC) $(LDFLAGS) -shared -o $@ $< $(LDLIBS)
