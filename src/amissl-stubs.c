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

#include <proto/amissl.h>

/* Parenthesis around function names in prototypes is to stop the preprocessor
 * from ruining them by doing unwanted macro expansion.
 *
 * These functions need to be implemented as stubs as libssh2 takes a pointer
 * to them and expects them to use a standard C function call ABI.
 */

const EVP_CIPHER *(EVP_aes_128_cbc)(void)
{
	return EVP_aes_128_cbc();
}

const EVP_CIPHER *(EVP_aes_192_cbc)(void)
{
	return EVP_aes_192_cbc();
}

const EVP_CIPHER *(EVP_aes_256_cbc)(void)
{
	return EVP_aes_256_cbc();
}

const EVP_CIPHER *(EVP_aes_128_ctr)(void)
{
	return EVP_aes_128_ctr();
}

const EVP_CIPHER *(EVP_aes_192_ctr)(void)
{
	return EVP_aes_192_ctr();
}

const EVP_CIPHER *(EVP_aes_256_ctr)(void)
{
	return EVP_aes_256_ctr();
}

const EVP_CIPHER *(EVP_bf_cbc)(void)
{
	return EVP_bf_cbc();
}

const EVP_CIPHER *(EVP_cast5_cbc)(void)
{
	return EVP_cast5_cbc();
}

const EVP_CIPHER *(EVP_des_ede3_cbc)(void)
{
	return EVP_des_ede3_cbc();
}

const EVP_CIPHER *(EVP_rc4)(void)
{
	return EVP_rc4();
}

EVP_PKEY *(PEM_read_bio_PrivateKey)(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
	return PEM_read_bio_PrivateKey(bp, x, cb, u);
}

DSA *(PEM_read_bio_DSAPrivateKey)(BIO *bp, DSA **x, pem_password_cb *cb, void *u)
{
	return PEM_read_bio_DSAPrivateKey(bp, x, cb, u);
}

RSA *(PEM_read_bio_RSAPrivateKey)(BIO *bp, RSA **x, pem_password_cb *cb, void *u)
{
	return PEM_read_bio_RSAPrivateKey(bp, x, cb, u);
}

EC_KEY *(PEM_read_bio_ECPrivateKey)(BIO *bp, EC_KEY **x, pem_password_cb *cb, void *u)
{
	return PEM_read_bio_ECPrivateKey(bp, x, cb, u);
}
