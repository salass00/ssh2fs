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

#include "ssh2fs.h"
#include "ssh2-handler_rev.h"

#include <proto/intuition.h>
#include <libraries/mui.h>
#include <proto/muimaster.h>

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

struct Library *MUIMasterBase;

char *request_password(unsigned int auth_pw, ...)
{
	struct Library *IntuitionBase;
	char           *password = NULL;
	va_list         ap;

	va_start(ap, auth_pw);

	IntuitionBase = OpenLibrary((CONST_STRPTR)"intuition.library", 39);
	if (IntuitionBase != NULL)
	{
		struct Library *muibase;

		MUIMasterBase = muibase = OpenLibrary((CONST_STRPTR)"muimaster.library", 19);
		if (muibase != NULL)
		{
			char    bodytext[256];
			Object *app, *winobj, *strobj, *okbtn, *cancelbtn;

			if (auth_pw == AUTH_PUBLICKEY)
				vsnprintf(bodytext, sizeof(bodytext), "Enter passphrase for key file '%s'", ap);
			else
				vsnprintf(bodytext, sizeof(bodytext), "Enter password for %s@%s", ap);

			app = ApplicationObject,
				SubWindow, winobj = WindowObject,
					MUIA_Window_Title, VERS,
					WindowContents, VGroup,
						Child, TextObject,
							MUIA_Text_Contents, bodytext,
						End,
						Child, strobj = StringObject,
							MUIA_Frame, MUIV_Frame_String,
							//MUIA_InputMode, MUIV_InputMode_RelVerify,
							MUIA_String_MaxLen, 256,
							MUIA_String_Secret, TRUE,
						End,
						Child, HGroup,
							Child, okbtn = TextObject,
								MUIA_Frame, MUIV_Frame_Button,
								MUIA_Background, MUII_ButtonBack,
								MUIA_Font, MUIV_Font_Button,
								MUIA_InputMode, MUIV_InputMode_RelVerify,
								MUIA_Text_PreParse, "\33c",
								MUIA_Text_Contents, "Ok",
								MUIA_Text_HiChar, 'o',
							End,
							Child, RectangleObject,
							End,
							Child, cancelbtn = TextObject,
								MUIA_Frame, MUIV_Frame_Button,
								MUIA_Background, MUII_ButtonBack,
								MUIA_Font, MUIV_Font_Button,
								MUIA_InputMode, MUIV_InputMode_RelVerify,
								MUIA_Text_PreParse, "\33c",
								MUIA_Text_Contents, "Cancel",
								MUIA_Text_HiChar, 'c',
							End,
						End,
					End,
				End,
			End;

			if (app != NULL)
			{
				ULONG signals = 0;
				ULONG id;

				DoMethod(winobj, MUIM_Notify, MUIA_Window_Activate, TRUE, strobj,
					2, MUIM_GoActive, 0);

				DoMethod(winobj, MUIM_Notify, MUIA_Window_CloseRequest, TRUE, MUIV_Notify_Application,
					2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);

				DoMethod(strobj, MUIM_Notify, MUIA_String_Acknowledge, MUIV_EveryTime, MUIV_Notify_Application,
					2, MUIM_Application_ReturnID, 1337);

				DoMethod(okbtn, MUIM_Notify, MUIA_Pressed, FALSE, MUIV_Notify_Application,
					2, MUIM_Application_ReturnID, 1337);

				DoMethod(cancelbtn, MUIM_Notify, MUIA_Pressed, FALSE, MUIV_Notify_Application,
					2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);

				set(winobj, MUIA_Window_Open, TRUE);

				if (XGET(winobj, MUIA_Window_Open))
				{
					DoMethod(strobj, MUIM_GoActive, 0);

					while ((id = DoMethod(app, MUIM_Application_NewInput, &signals)) != MUIV_Application_ReturnID_Quit)
					{
						if (id == 1337)
						{
							const char *buffer;
							buffer = (const char *)XGET(strobj, MUIA_String_Contents);
							if (buffer != NULL && buffer[0] != '\0')
							{
								password = strdup(buffer);
								break;
							}
							else
							{
								DoMethod(strobj, MUIM_GoActive, 0);
							}
						}

						if (signals)
						{
							signals = Wait(signals | SIGBREAKF_CTRL_C);
							if (signals & SIGBREAKF_CTRL_C) break;
						}
					}
				}

				MUI_DisposeObject(app);
			}

			CloseLibrary(muibase);
		}

		CloseLibrary(IntuitionBase);
	}

	va_end(ap);

	return password;
}

#if 0
#include <stdlib.h>

int main(void)
{
	char *password;

	password = request_password(AUTH_PUBLICKEY, "L:id_rsa");
	printf("password: %s\n", password ?: "(null)");
	free(password);

	return 0;
}
#endif

