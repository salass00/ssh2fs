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
       reqtools-password-req.c

ARCH_020 = -mcpu=68020 -mtune=68020-60
OBJS_020 = $(addprefix obj/68020/,$(SRCS:.c=.o))
DEPS_020 = $(OBJS_020:.o=.d)

ARCH_060 = -mcpu=68060 -mtune=68060
OBJS_060 = $(addprefix obj/68060/,$(SRCS:.c=.o))
DEPS_060 = $(OBJS_060:.o=.d)

.PHONY: all
all: bin/$(TARGET).020 bin/$(TARGET).060

-include $(DEPS_020)
-include $(DEPS_060)

obj/68020/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) -MM -MP -MT $(@:.o=.d) -MT $@ -MF $(@:.o=.d) $(ARCH_020) $(CFLAGS) $<
	$(CC) $(ARCH_020) $(CFLAGS) -c -o $@ $<

obj/68060/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) -MM -MP -MT $(@:.o=.d) -MT $@ -MF $(@:.o=.d) $(ARCH_060) $(CFLAGS) $<
	$(CC) $(ARCH_060) $(CFLAGS) -c -o $@ $<

.PHONY: build-libssh2-020 build-libssh2-060

build-libssh2-020:
	$(MAKE) -C $(LIBSSH2DIR) bin/libssh2.a.020

build-libssh2-060:
	$(MAKE) -C $(LIBSSH2DIR) bin/libssh2.a.060

$(LIBSSH2DIR)/bin/libssh2.a.020: build-libssh2-020
	@true

$(LIBSSH2DIR)/bin/libssh2.a.060: build-libssh2-060
	@true

bin/$(TARGET).020: $(OBJS_020) $(LIBSSH2DIR)/bin/libssh2.a.020
	@mkdir -p $(dir $@)
	$(CC) $(LDFLAGS) -o $@.debug $^ $(LIBS)
	$(STRIP) $(STRIPFLAGS) -o $@ $@.debug

bin/$(TARGET).060: $(OBJS_060) $(LIBSSH2DIR)/bin/libssh2.a.060
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

