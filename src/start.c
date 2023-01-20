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

#include <exec/alerts.h>
#include <utility/utility.h>
#include <proto/utility.h>
#include <bsdsocket/socketbasetags.h>

#include <errno.h>

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct UtilityBase *UtilityBase;
struct Library *aroscbase;
struct Library *FileSysBoxBase;
struct Library *SocketBase;

__attribute__((used)) const char verstag[] = VERSTAG;

int _start(void)
{
	struct Process *me;
	struct Message *msg = NULL;
	struct DosPacket *pkt = NULL;
	int rc = RETURN_ERROR;

	SysBase = *(struct ExecBase **)4;

	DOSBase = (struct DosLibrary *)OpenLibrary((CONST_STRPTR)DOSNAME, 39);
	if (DOSBase == NULL)
	{
		Alert(AG_OpenLib | AO_DOSLib);
		goto cleanup;
	}

	UtilityBase = (struct UtilityBase *)OpenLibrary((CONST_STRPTR)UTILITYNAME, 39);
	if (UtilityBase == NULL)
	{
		Alert(AG_OpenLib | AO_UtilityLib);
		goto cleanup;
	}

	me = (struct Process *)FindTask(NULL);
	if (me->pr_CLI != ZERO)
	{
		/* CLI startup */
		PutStr((CONST_STRPTR)VERS);
		rc = RETURN_OK;
		goto cleanup;
	}

	WaitPort(&me->pr_MsgPort);
	msg = GetMsg(&me->pr_MsgPort);
	if (msg->mn_Node.ln_Name == NULL)
	{
		/* WB startup */
		rc = RETURN_FAIL;
		goto cleanup;
	}

	pkt = (struct DosPacket *)msg->mn_Node.ln_Name;
	msg = NULL;

	aroscbase = OpenLibrary((CONST_STRPTR)"arosc.library", 41);
	if (aroscbase == NULL)
	{
		goto cleanup;
	}

	FileSysBoxBase = OpenLibrary((CONST_STRPTR)"filesysbox.library", 54);
	if (FileSysBoxBase == NULL)
	{
		goto cleanup;
	}

	SocketBase = OpenLibrary((CONST_STRPTR)"bsdsocket.library", 4);
	if (SocketBase == NULL)
	{
		goto cleanup;
	}

	if (SocketBaseTags(
		SBTM_SETVAL(SBTC_BREAKMASK),     0, /* Disable CTRL-C checking in WaitSelect() */
		SBTM_SETVAL(SBTC_ERRNOLONGPTR),  &errno,
		//SBTM_SETVAL(SBTC_HERRNOLONGPTR), &h_errno // TODO
		TAG_END))
	{
		goto cleanup;
	}

	if (setup_malloc() == FALSE)
	{
		goto cleanup;
	}

	rc = ssh2fs_main(pkt);

	/* Set to NULL so we don't reply the packet twice */
	pkt = NULL;

cleanup:

	cleanup_malloc();

	if (SocketBase == NULL)
	{
		CloseLibrary(SocketBase);
		SocketBase = NULL;
	}

	if (FileSysBoxBase == NULL)
	{
		CloseLibrary(FileSysBoxBase);
		FileSysBoxBase = NULL;
	}

	if (aroscbase != NULL)
	{
		CloseLibrary(aroscbase);
		aroscbase = NULL;
	}

	if (UtilityBase != NULL)
	{
		CloseLibrary((struct Library *)UtilityBase);
		UtilityBase = NULL;
	}

	if (DOSBase != NULL)
	{
		CloseLibrary((struct Library *)DOSBase);
		DOSBase = NULL;
	}

	if (msg != NULL)
	{
		Forbid();
		ReplyMsg(msg);
	}

	return rc;
}

