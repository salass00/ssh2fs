CC     = m68k-amigaos-gcc
AR     = m68k-amigaos-ar
RANLIB = m68k-amigaos-ranlib

OPTIMIZE = -O2
DEBUG    = -g
WARNINGS = -Wall -Werror -Wwrite-strings -Wno-deprecated-declarations
INCLUDES = -I./include -I./src
DEFINES  = -DLIBSSH2_OPENSSL -DLIBSSH2_DH_GEX_NEW -DLIBSSH2_HAVE_ZLIB \
           -DLIBSSH2_AMIGADOS -DNDEBUG
#DEFINES += -DLIBSSH2DEBUG

CFLAGS  = -noixemul --std=gnu99 $(OPTIMIZE) $(DEBUG) $(WARNINGS) $(INCLUDES) $(DEFINES)

SRCS = agent.c bcrypt_pbkdf.c blowfish.c channel.c comp.c crypt.c global.c \
       hostkey.c keepalive.c kex.c knownhost.c libgcrypt.c mac.c mbedtls.c \
       misc.c openssl.c packet.c pem.c publickey.c scp.c session.c sftp.c \
       transport.c userauth.c version.c wincng.c

ARCH_020 = -mcpu=68020 -mtune=68020-60
OBJS_020 = $(addprefix obj/68020/,$(SRCS:.c=.o))
DEPS_020 = $(OBJS_020:.o=.d)

ARCH_060 = -mcpu=68060 -mtune=68060
OBJS_060 = $(addprefix obj/68060/,$(SRCS:.c=.o))
DEPS_060 = $(OBJS_060:.o=.d)

.PHONY: all
all: bin/libssh2.a.020 bin/libssh2.a.060

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

bin/libssh2.a.020: $(OBJS_020)
	@mkdir -p $(dir $@)
	$(AR) -crv $@ $^
	$(RANLIB) $@

bin/libssh2.a.060: $(OBJS_060)
	@mkdir -p $(dir $@)
	$(AR) -crv $@ $^
	$(RANLIB) $@

.PHONY: clean
clean:
	rm -rf bin obj

