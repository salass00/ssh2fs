/*
 * ssh2-handler - SSH2 file system client
 *
 * Copyright (C) 2018-2023 Fredrik Wikstrom <fredrik@a500.org>
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

#define LIBRARIES_Z_H
#include <zlib.h>
#include <proto/z.h>

int deflateInit_ (z_streamp strm, int level, const char *version, int stream_size) {
	const char *my_version = (const char *)ZlibVersion();
	if (version == Z_NULL || version[0] != my_version[0] || stream_size != sizeof(z_stream)) {
		return Z_VERSION_ERROR;
	}
	return DeflateInit(strm, level);
}

int deflate (z_streamp strm, int flush) {
	return Deflate(strm, flush);
}

int deflateEnd (z_streamp strm) {
	return DeflateEnd(strm);
}

int inflateInit_ (z_streamp strm, const char *version, int stream_size) {
	const char *my_version = (const char *)ZlibVersion();
	if (version == Z_NULL || version[0] != my_version[0] || stream_size != sizeof(z_stream)) {
		return Z_VERSION_ERROR;
	}
	return InflateInit(strm);
}

int inflate (z_streamp strm, int flush) {
	return Inflate(strm, flush);
}

int inflateEnd (z_streamp strm) {
	return InflateEnd(strm);
}

