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

#include <proto/filesysbox.h>
#include <sys/time.h>
#include <time.h>

extern struct fuse_context *_fuse_context_;

#define UNIXTIMEOFFSET 252460800

int gettimeofday(struct timeval *tvp, struct timezone *tzp)
{
	struct FbxFS *fs = fuse_get_context()->fuse;
	LONG gmtoffset = 0;

	/* Get difference to GMT time in minutes */
	FbxQueryFSTags(fs,
		FBXT_GMT_OFFSET, (Tag)&gmtoffset,
		TAG_END);

	if (tvp != NULL)
	{
		FbxGetSysTime(fs, tvp);
		tvp->tv_sec += UNIXTIMEOFFSET + (gmtoffset * 60);
	}

	if (tzp != NULL)
	{
		tzp->tz_minuteswest = gmtoffset;
		tzp->tz_dsttime     = -1;
	}

	return 0;
}

time_t time(time_t *tp)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0)
		return -1;

	if (tp != NULL)
		*tp = tv.tv_sec;

	return tv.tv_sec;
}

