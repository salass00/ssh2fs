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

#include "ssh2fs.h"
#include "ssh2-handler_rev.h"

#include <proto/intuition.h>
#include <classes/requester.h>
#include <proto/requester.h>
#include <clib/alib_protos.h>

#include <stdio.h>
#include <stdarg.h>

#ifndef REQ_Image
#define REQ_Image (REQ_Dummy+7)
#endif
#ifndef REQIMAGE_QUESTION
#define REQIMAGE_QUESTION (4)
#endif
#ifndef REQS_ReturnEnds
#define REQS_ReturnEnds (REQS_Dummy+8)
#endif

char *request_password(unsigned int auth_pw, ...)
{
	struct Library *IntuitionBase;
	char           *password = NULL;
	va_list         ap;

	va_start(ap, auth_pw);

	IntuitionBase = OpenLibrary((CONST_STRPTR)"intuition.library", 39);
	if (IntuitionBase != NULL)
	{
		struct Library *RequesterBase;
		Class          *RequesterClass;

		RequesterBase = OpenLibrary((CONST_STRPTR)"requester.class", 42);
		if (RequesterBase != NULL)
		{
			struct Screen *screen;

			RequesterClass = REQUESTER_GetClass();

			screen = LockPubScreen(NULL);
			if (screen != NULL)
			{
				char    bodytext[256];
				char    buffer[256];
				Object *reqobj;

				buffer[0] = '\0';

				if (auth_pw == AUTH_PUBLICKEY)
					vsnprintf(bodytext, sizeof(bodytext), "Enter passphrase for key file '%s'", ap);
				else
					vsnprintf(bodytext, sizeof(bodytext), "Enter password for %s@%s", ap);

				reqobj = NewObject(RequesterClass, NULL,
					REQ_Type,        REQTYPE_STRING,
					REQ_Image,       REQIMAGE_QUESTION,
					REQ_TitleText,   (IPTR)VERS,
					REQ_BodyText,    (IPTR)bodytext,
					REQ_GadgetText,  (IPTR)"_Ok|_Cancel",
					REQS_AllowEmpty, FALSE,
					REQS_Invisible,  TRUE,
					REQS_Buffer,     (IPTR)buffer,
					REQS_MaxChars,   sizeof(buffer),
					REQS_ReturnEnds, TRUE,
					TAG_END);

				if (reqobj != NULL)
				{
					struct orRequest reqmsg;
					LONG             result;

					reqmsg.MethodID  = RM_OPENREQ;
					reqmsg.or_Attrs  = NULL;
					reqmsg.or_Window = NULL;
					reqmsg.or_Screen = screen;

					result = DoMethodA(reqobj, (Msg)&reqmsg);

					if (result && buffer[0] != '\0')
					{
						password = strdup(buffer);
					}

					DisposeObject(reqobj);
				}

				UnlockPubScreen(NULL, screen);
			}

			CloseLibrary(RequesterBase);
		}

		CloseLibrary(IntuitionBase);
	}

	va_end(ap);

	return password;
}

