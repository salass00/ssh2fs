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

#include "ssh2fs.h"
#include "ssh2-handler_rev.h"

#include <libraries/reqtools.h>
#include <proto/reqtools.h>

#include <stdio.h>
#include <stdarg.h>

char *request_password(unsigned int auth_pw, ...)
{
	struct Library *ReqToolsBase;
	char           *password = NULL;
	va_list         ap;

	va_start(ap, auth_pw);

	ReqToolsBase = OpenLibrary((CONST_STRPTR)"reqtools.library", 38);
	if (ReqToolsBase != NULL)
	{
		char  bodytext[256];
		char  buffer[256];
		ULONG result;

		buffer[0] = '\0';

		if (auth_pw == AUTH_PUBLICKEY)
			vsnprintf(bodytext, sizeof(bodytext), "Enter passphrase for key file '%s'", ap);
		else
			vsnprintf(bodytext, sizeof(bodytext), "Enter password for %s@%s", ap);

		result = rtGetString((UBYTE *)buffer, sizeof(buffer)-1, (char *)VERS, NULL,
			RTGS_TextFmt,    (IPTR)bodytext,
			RT_Underscore,   '_',
			RTGS_GadFmt,     (IPTR)"_Ok|_Cancel",
			RTGS_AllowEmpty, FALSE,
			RTGS_Invisible,  TRUE,
			TAG_END);

		if (result && buffer[0] != '\0')
		{
			password = strdup(buffer);
		}

		CloseLibrary(ReqToolsBase);
	}

	va_end(ap);

	return password;
}

