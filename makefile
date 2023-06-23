CC    = m68k-amigaos-gcc
STRIP = m68k-amigaos-strip

TARGET  = ssh2-handler
VERSION = 53

LIBSSH2DIR = libssh2-1.10.0

OPTIMIZE = -O2 -fomit-frame-pointer
DEBUG    = -g
INCLUDES = -I. -I./$(LIBSSH2DIR)/include
WARNINGS = -Wall -Werror -Wwrite-strings

CFLAGS  = -noixemul $(OPTIMIZE) $(DEBUG) $(INCLUDES) $(WARNINGS)
LDFLAGS = -noixemul -nostartfiles
LIBS    = -lamisslstubs -ldebug

STRIPFLAGS = -R.comment

SRCS = start.c main.c time.c malloc.c strlcpy.c snprintf.c zlib-stubs.c \
       reaction-password-req.c

ARCH_000 = -mcpu=68000 -mtune=68000
OBJS_000 = $(addprefix obj/68000/,$(SRCS:.c=.o))
DEPS_000 = $(OBJS_000:.o=.d)

ARCH_020 = -mcpu=68020 -mtune=68020-60
OBJS_020 = $(addprefix obj/68020/,$(SRCS:.c=.o))
DEPS_020 = $(OBJS_020:.o=.d)

.PHONY: all
all: bin/$(TARGET).000 bin/$(TARGET).020

-include $(DEPS_000)
-include $(DEPS_020)

obj/68000/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) -MM -MP -MT $(@:.o=.d) -MT $@ -MF $(@:.o=.d) $(ARCH_000) $(CFLAGS) $<
	$(CC) $(ARCH_000) $(CFLAGS) -c -o $@ $<

obj/68020/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) -MM -MP -MT $(@:.o=.d) -MT $@ -MF $(@:.o=.d) $(ARCH_020) $(CFLAGS) $<
	$(CC) $(ARCH_020) $(CFLAGS) -c -o $@ $<

.PHONY: build-libssh2-000 build-libssh2-020

build-libssh2-000:
	$(MAKE) -C $(LIBSSH2DIR) bin/libssh2.a.000

build-libssh2-020:
	$(MAKE) -C $(LIBSSH2DIR) bin/libssh2.a.020

$(LIBSSH2DIR)/bin/libssh2.a.000: build-libssh2-000
	@true

$(LIBSSH2DIR)/bin/libssh2.a.020: build-libssh2-020
	@true

bin/$(TARGET).000: $(OBJS_000) $(LIBSSH2DIR)/bin/libssh2.a.000
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@.debug $^ $(LIBS)
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

bin/$(TARGET).020: $(OBJS_020) $(LIBSSH2DIR)/bin/libssh2.a.020
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@.debug $^ $(LIBS)
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

.PHONY: clean
clean:
	$(MAKE) -C $(LIBSSH2DIR) clean
	rm -rf bin obj

.PHONY: revision
revision:
	bumprev -e si $(VERSION) $(TARGET)

