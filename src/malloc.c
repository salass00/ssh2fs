/*
 * ssh2-handler - SSH2 file system client
 *
 * Copyright (C) 2018-2020 Fredrik Wikstrom <fredrik@a500.org>
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

#include <proto/exec.h>

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static APTR mempool;

int setup_malloc(void)
{
	mempool = CreatePool(MEMF_ANY, 8192, 2048);
	return mempool != NULL;
}

void cleanup_malloc(void)
{
	DeletePool(mempool);
}

void *malloc(size_t size)
{
	size_t *mem;

	/* Check for overflow */
	if (size > (SIZE_MAX - sizeof(size_t)))
	{
		errno = EINVAL;
		return NULL;
	}

	mem = AllocPooled(mempool, size + sizeof(size_t));
	if (mem == NULL)
	{
		errno = ENOMEM;
		return NULL;
	}

	*mem++ = size;
	return mem;
}

static inline size_t malloc_usable_size(void *ptr)
{
	return ((size_t *)ptr)[-1];
}

void free(void *ptr)
{
	if (ptr != NULL)
	{
		size_t size = malloc_usable_size(ptr);
		FreePooled(mempool, ptr, size + sizeof(size_t));
	}
}

void *calloc(size_t num, size_t ns)
{
	size_t size = num * ns;
	void *ptr;

	/* Check for overflow */
	if (num != 0 && ns != 0 && (size / ns) != num)
	{
		errno = EINVAL;
		return NULL;
	}

	ptr = malloc(size);
	if (ptr != NULL)
	{
		bzero(ptr, size);
	}

	return ptr;
}

void *realloc(void *old, size_t new_size)
{
	size_t old_size;
	void *new;

	if (old == NULL)
	{
		return malloc(new_size);
	}

	old_size = malloc_usable_size(old);
	if (old_size >= new_size)
		return old;

	new = malloc(new_size);
	if (new != NULL)
	{
		memcpy(new, old, old_size);
	}

	free(old);
	return new;
}

char *strdup(const char *old)
{
	size_t size = strlen(old) + 1;
	char *new;

	new = malloc(size);
	if (new != NULL)
	{
		memcpy(new, old, size);
	}

	return new;
}

