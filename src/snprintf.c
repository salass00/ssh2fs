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

#include <stdio.h>

#include <exec/types.h>
#include <string.h>

typedef int (*_putc_cb)(char ch, void *udata);

static int _dofmt(_putc_cb cb, void *cb_data, const char *fmt, va_list ap);

int snprintf(char *buffer, size_t maxlen, const char *fmt, ...) {
	va_list ap;
	int count;

	va_start(ap, fmt);
	count = vsnprintf(buffer, maxlen, fmt, ap);
	va_end(ap);

	return count;
}

typedef struct {
	char *buffer;
	size_t space;
} _putc_data;

int putc_cb(char ch, void *udata) {
	_putc_data *cb_data = udata;

	if (cb_data->space > 0) {
		if (--cb_data->space > 0)
			*cb_data->buffer++ = ch;
		else
			*cb_data->buffer++ = '\0';
	}

	return 0;
}

int vsnprintf(char *buffer, size_t maxlen, const char *fmt, va_list ap) {
	_putc_data cb_data;
	int count;

	cb_data.buffer = buffer;
	cb_data.space  = maxlen;

	count = _dofmt(putc_cb, &cb_data, fmt, ap);

	/* Make sure that the output is NUL-terminated. */
	putc_cb('\0', &cb_data);

	return count;
}

static void reverse(char *str, size_t len) {
	char *start = str;
	char *end = str + len - 1;
	char tmp;

	while (start < end) {
		tmp = *end;
		*end-- = *start;
		*start++ = tmp;
	}
}

static size_t itoa(unsigned num, char *dst, unsigned base,
	char issigned, char addplus, char uppercase)
{
	char a = uppercase ? 'A' : 'a';
	char negative = FALSE;
	char *d = dst;
	size_t len;

	if (num == 0) {
		*d++ = '0';
		return d - dst;
	}

	if (issigned && (int)num < 0 && base == 10) {
		negative = TRUE;
		num = -num;
	}

	while (num != 0) {
		unsigned rem = num % base;
		num /= base;
		*d++ = (rem > 9) ? (rem - 10 + a) : (rem + '0');
	}

	if (negative)
		*d++ = '-';
	else if (addplus)
		*d++ = '+';

	len = d - dst;
	reverse(dst, len);
	return len;
}

static size_t lltoa(unsigned long long num, char *dst, unsigned base,
	char issigned, char addplus, char uppercase)
{
	char a = uppercase ? 'A' : 'a';
	char negative = FALSE;
	char *d = dst;
	size_t len;

	if (num == 0) {
		*d++ = '0';
		return d - dst;
	}

	if (issigned && (signed long long)num < 0 && base == 10) {
		negative = TRUE;
		num = -num;
	}

	while (num != 0) {
		unsigned rem = num % base;
		num /= base;
		*d++ = (rem > 9) ? (rem - 10 + a) : (rem + '0');
	}

	if (negative)
		*d++ = '-';
	else if (addplus)
		*d++ = '+';

	len = d - dst;
	reverse(dst, len);
	return len;
}

#define PUTC(ch) \
	do { \
		if (cb((ch), cb_data) == 0) \
			count++; \
		else \
			return -1; \
	} while (0)

static int _dofmt(_putc_cb cb, void *cb_data, const char *fmt, va_list ap) {
	char ch;
	int count = 0;

	while ((ch = *fmt++) != '\0') {
		if (ch != '%') {
			PUTC(ch);
		} else {
			char left = FALSE;
			char addplus = FALSE;
			char alternate = FALSE;
			char lead = ' ';
			size_t width = 0;
			size_t limit = 0;
			char longlong = FALSE;
			char uppercase;
			char tmp[128];
			const char *src;
			size_t len;

			if ((ch = *fmt++) == '\0')
				return count;

			while (TRUE) {
				if (ch == '-')
					left = TRUE;
				else if (ch == '+')
					addplus = TRUE;
				else if (ch == '#')
					alternate = TRUE;
				else if (ch == '0')
					lead = '0';
				else
					break;
				if ((ch = *fmt++) == '\0')
					return count;
			}

			while (ch >= '0' && ch <= '9') {
				width = 10 * width + (ch - '0');
				if ((ch = *fmt++) == '\0')
					return count;
			}

			if (ch == '.') {
				if ((ch = *fmt++) == '\0')
					return count;

				while (ch >= '0' && ch <= '9') {
					limit = 10 * limit + (ch - '0');
					if ((ch = *fmt++) == '\0')
						return count;
				}
			}

			if (ch == 'l' || ch == 'h') {
				if ((ch = *fmt++) == '\0')
					return count;
				if (ch == 'l') {
					longlong = TRUE;
					if ((ch = *fmt++) == '\0')
						return count;
				}
			}

			switch (ch) {
			case '%':
				PUTC('%');
				break;
			case 'D':
			case 'd':
			case 'I':
			case 'i':
				uppercase = (ch == 'D' || ch == 'I') ? TRUE : FALSE;
				if (longlong)
					len = lltoa(va_arg(ap, long long), tmp, 10, TRUE, addplus, uppercase);
				else
					len = itoa(va_arg(ap, int), tmp, 10, TRUE, addplus, uppercase);

				src = tmp;
				if (width > len)
					width -= len;
				else
					width = 0;

				if (!left)
					while (width--)
						PUTC(lead);

				while (len--)
					PUTC(*src++);

				if (left)
					while (width--)
						PUTC(' ');
				break;
			case 'U':
			case 'u':
				uppercase = (ch == 'X') ? TRUE : FALSE;
				if (longlong)
					len = lltoa(va_arg(ap, long long), tmp, 10, FALSE, addplus, uppercase);
				else
					len = itoa(va_arg(ap, int), tmp, 10, FALSE, addplus, uppercase);

				src = tmp;
				if (width > len)
					width -= len;
				else
					width = 0;

				if (!left)
					while (width--)
						PUTC(lead);

				while (len--)
					PUTC(*src++);

				if (left)
					while (width--)
						PUTC(' ');
				break;
			case 'X':
			case 'x':
				uppercase = (ch == 'X') ? TRUE : FALSE;
				if (longlong)
					len = lltoa(va_arg(ap, long long), tmp, 16, FALSE, addplus, uppercase);
				else
					len = itoa(va_arg(ap, int), tmp, 16, FALSE, addplus, uppercase);

				src = tmp;
				if (width > len)
					width -= len;
				else
					width = 0;

				if (!left)
					while (width--)
						PUTC(lead);

				while (len--)
					PUTC(*src++);

				if (left)
					while (width--)
						PUTC(' ');
				break;
			case 'P':
			case 'p':
				uppercase = (ch == 'P') ? TRUE : FALSE;
				if (longlong)
					len = lltoa(va_arg(ap, long long), tmp, 16, FALSE, FALSE, uppercase);
				else
					len = itoa(va_arg(ap, int), tmp, 16, FALSE, FALSE, uppercase);

				src = tmp;
				width = 8;
				lead = '0';
				if (width > len)
					width -= len;
				else
					width = 0;

				if (alternate && tmp[0] != '0') {
					PUTC('0');
					PUTC('x');
				}

				while (width--)
					PUTC(lead);

				while (len--)
					PUTC(*src++);
				break;
			case 'S':
			case 's':
				src = va_arg(ap, const char *);
				if (src == NULL)
					src = "(null)";

				len = strlen(src);

				if (limit != 0 && len > limit)
					len = limit;

				if (width > len)
					width -= len;
				else
					width = 0;

				if (!left)
					while (width--)
						PUTC(' ');

				while (len--)
					PUTC(*src++);

				if (left)
					while (width--)
						PUTC(' ');
				break;
			}
		}
	}

	return count;
}

