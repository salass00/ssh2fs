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

#define LIBRARIES_Z_H
#include <zlib.h>
#include <proto/z.h>

const char *zlibVersion (void) {
	return (const char *)ZlibVersion();
}

int deflateInit_ (z_streamp strm, int level, const char *version, int stream_size) {
	const char *my_version = (const char *)ZlibVersion();
	if (version == Z_NULL || version[0] != my_version[0] || stream_size != sizeof(z_stream)) {
		return Z_VERSION_ERROR;
	}
	return DeflateInit(strm, level);
}

int deflateInit2_ (z_streamp strm, int level, int method, int windowBits, int memLevel,
	int strategy, const char *version, int stream_size)
{
	const char *my_version = (const char *)ZlibVersion();
	if (version == Z_NULL || version[0] != my_version[0] || stream_size != sizeof(z_stream)) {
		return Z_VERSION_ERROR;
	}
	return DeflateInit2(strm, level, method, windowBits, memLevel, strategy);
}

int deflateSetDictionary (z_streamp strm, const Bytef *dictionary, uInt dictLength) {
	return DeflateSetDictionary(strm, dictionary, dictLength);
}

int deflate (z_streamp strm, int flush) {
	return Deflate(strm, flush);
}

int deflateCopy (z_streamp dest, z_streamp source) {
	return DeflateCopy(dest, source);
}

int deflateReset (z_streamp strm) {
	return DeflateReset(strm);
}

int deflateParams (z_streamp strm, int level, int strategy) {
	return DeflateParams(strm, level, strategy);
}

int deflateTune (z_streamp strm, int good_length, int max_lazy, int nice_length,
	int max_chain)
{
	return DeflateTune(strm, good_length, max_lazy, nice_length, max_chain);
}

uLong deflateBound (z_streamp strm, uLong sourceLen) {
	return DeflateBound(strm, sourceLen);
}

int deflatePrime (z_streamp strm, int bits, int value) {
	return DeflatePrime(strm, bits, value);
}

int deflateSetHeader (z_streamp strm, gz_headerp head) {
	return DeflateSetHeader(strm, head);
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

int inflateInit2_ (z_streamp strm, int windowBits, const char *version, int stream_size) {
	const char *my_version = (const char *)ZlibVersion();
	if (version == Z_NULL || version[0] != my_version[0] || stream_size != sizeof(z_stream)) {
		return Z_VERSION_ERROR;
	}
	return InflateInit2(strm, windowBits);
}

int inflateGetDictionary (z_streamp strm, Bytef *dictionary, uInt *dictLength) {
	return InflateGetDictionary(strm, dictionary, (ULONG *)dictLength);
}

int inflateSetDictionary (z_streamp strm, const Bytef *dictionary, uInt dictLength) {
	return InflateSetDictionary(strm, dictionary, dictLength);
}

int inflate (z_streamp strm, int flush) {
	return Inflate(strm, flush);
}

int inflateSync (z_streamp strm) {
	return InflateSync(strm);
}

int inflateCopy (z_streamp dest, z_streamp source) {
	return InflateCopy(dest, source);
}

int inflateReset (z_streamp strm) {
	return InflateReset(strm);
}

int inflatePrime (z_streamp strm, int bits, int value) {
	return InflatePrime(strm, bits, value);
}

int inflateGetHeader (z_streamp strm, gz_headerp head) {
	return InflateGetHeader(strm, head);
}

int inflateEnd (z_streamp strm) {
	return InflateEnd(strm);
}

int inflateBackInit_ (z_streamp strm, int windowBits, unsigned char *window,
	const char *version, int stream_size)
{
	const char *my_version = (const char *)ZlibVersion();
	if (version == Z_NULL || version[0] != my_version[0] || stream_size != sizeof(z_stream)) {
		return Z_VERSION_ERROR;
	}
	return InflateBackInit(strm, windowBits, window);
}

int inflateBack (z_streamp strm, in_func in, void *in_desc, out_func out, void *out_desc) {
	return InflateBack(strm, in, in_desc, out, out_desc);
}

int inflateBackEnd (z_streamp strm) {
	return InflateBackEnd(strm);
}

int compress (Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen) {
	return Compress(dest, (ULONG *)destLen, source, sourceLen);
}

int compress2 (Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen, int level) {
	return Compress2(dest, (ULONG *)destLen, source, sourceLen, level);
}

uLong compressBound (uLong sourceLen) {
	return CompressBound(sourceLen);
}

int uncompress (Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen) {
	return Uncompress(dest, (ULONG *)destLen, source, sourceLen);
}

uLong adler32 (uLong adler, const Bytef *buf, uInt len) {
	return Adler32(adler, buf, len);
}

uLong adler32_combine (uLong adler1, uLong adler2, z_off_t len2) {
	return Adler32Combine(adler1, adler2, len2);
}

uLong crc32 (uLong crc, const Bytef *buf, uInt len) {
	return CRC32(crc, buf, len);
}

uLong crc32_combine (uLong crc1, uLong crc2, z_off_t len2) {
	return CRC32Combine(crc1, crc2, len2);
}

const char *zError (int err) {
	return (const char *)ZError(err);
}

