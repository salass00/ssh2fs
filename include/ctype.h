/*
 * ssh2-handler - SSH2 file system client
 *
 * Copyright (C) 2018-2026 Fredrik Wikstrom <fredrik@a500.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS `AS IS'
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SSH2FS_CTYPE_H
#define SSH2FS_CTYPE_H

#ifndef __AROS__
#include_next <ctype.h>
#else

/* These replacement functions only support ASCII */

static inline int isupper(int c)
{
	return (c >= 'A' && c <= 'Z');
}

static inline int islower(int c)
{
	return (c >= 'a' && c <= 'z');
}

static inline int isalpha(int c)
{
	return (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z');
}

static inline int isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

static inline int isxdigit(int c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'A' && c <= 'F') ||
	       (c >= 'a' && c <= 'f');
}

static inline int isspace(int c)
{
	return (c >= '\t' && c <= '\r') ||
	       c == ' ';
}

static inline int isprint(int c)
{
	return (c >= ' ' && c <= '~');
}

static inline int isgraph(int c)
{
	return (c >= '!' && c <= '~');
}

static inline int isblank(int c)
{
	return c == '\t' || c == ' ';
}

static inline int iscntrl(int c)
{
	return (c >= '\0' && c <= '\x1F') ||
	       c == '\x7F';
}

static inline int ispunct(int c)
{
	return (c >= '!' && c <= '/') ||
	       (c >= ':' && c <= '@') ||
	       (c >= '[' && c <= '`') ||
	       (c >= '{' && c <= '~');
}

static inline int isalnum(int c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z');
}

static inline int toupper(int c)
{
	if (c >= 'a' && c <= 'z')
		return c - ('a' - 'A');
	else
		return c;
}

static inline int tolower(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	else
		return c;
}

static inline int isascii(int c)
{
	return (c & ~0x7F) == 0;
}

static inline int toascii(int c)
{
	return c & 0x7F;
}

#endif /* __AROS__ */

#endif /* SSH2FS_CTYPE_H */

