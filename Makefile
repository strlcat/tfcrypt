VERSION:=$(shell cat VERSION)
override CFLAGS+=-D_TFCRYPT_VERSION=\"$(VERSION)\" -Wall
UPX=upx

ifneq (,$(DEBUG))
override CFLAGS+=-O0 -g
else
override CFLAGS+=-O3
endif

ifneq (,$(STATIC))
override LDFLAGS+=-static
endif

ifneq (,$(STRIP))
override LDFLAGS+=-s
endif

SRCS = $(wildcard *.c)
HDRS = $(wildcard *.h)
OBJS = $(SRCS:.c=.o)

all: tfcrypt

%.o: %.c VERSION $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

tfcrypt: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@

tfcrypt.upx: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -static -s $(OBJS) -o $@
	$(UPX) --best $@

clean:
	rm -f $(OBJS) tfcrypt tfcrypt.upx
