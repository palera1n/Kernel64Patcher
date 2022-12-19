CC		= gcc
CFLAGS	=
VERSION = $(shell git rev-parse HEAD | tr -d '\n')-$(shell git rev-list --count HEAD | tr -d '\n')

UNAME  := $(shell uname)
ifeq ($(UNAME), Darwin)
ARCH	= -arch x86_64 -arch arm64
else
ARCH	=
endif

.PHONY: all clean

all:
	$(CC) Kernel64Patcher.c $(ARCH) $(CFLAGS) -DVERSION=\"$(VERSION)\" -o Kernel64Patcher
	
clean:
	-$(RM) Kernel64Patcher