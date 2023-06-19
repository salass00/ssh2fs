CC    = m68k-amigaos-gcc
STRIP = m68k-amigaos-strip

TARGET  = ssh2-handler
VERSION = 53

LIBSSH2DIR = libssh2-1.10.0

OPTIMIZE = -m68020 -O2 -fomit-frame-pointer
DEBUG    = -g
INCLUDES = -I. -I./$(LIBSSH2DIR)/include
WARNINGS = -Wall -Werror -Wwrite-strings

CFLAGS  = -noixemul $(OPTIMIZE) $(DEBUG) $(INCLUDES) $(WARNINGS)
LDFLAGS = -noixemul -nostartfiles
LIBS    = -ldebug

STRIPFLAGS = -R.comment

SRCS = start.c main.c time.c malloc.c

OBJS = $(addprefix obj/,$(SRCS:.c=.o))

.PHONY: all
all: $(TARGET)

.PHONY: build-libssh2
build-libssh2:
	$(MAKE) -C $(LIBSSH2DIR) libssh2.a

obj/%.o: src/%.c
	@mkdir -p obj
	$(CC) $(CFLAGS) -c -o $@ $<

$(LIBSSH2DIR)/libssh2.a: build-libssh2
	@true

obj/start.o obj/main.o: src/ssh2fs.h $(TARGET)_rev.h

$(TARGET): $(OBJS) $(LIBSSH2DIR)/libssh2.a
	$(CC) $(LDFLAGS) -o $@.debug $^ $(LIBS)
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

.PHONY: clean
clean:
	$(MAKE) -C $(LIBSSH2DIR) clean
	rm -rf $(TARGET) $(TARGET).debug obj

.PHONY: revision
revision:
	bumprev -e si $(VERSION) $(TARGET)

