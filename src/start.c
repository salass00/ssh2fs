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
#include <proto/bsdsocket.h>

#ifndef __AROS__
#include <libraries/amisslmaster.h>
#include <proto/amisslmaster.h>
#include <proto/amissl.h>
#endif

#include <libssh2.h>
#include <errno.h>

#include <SDI/SDI_compiler.h>

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct UtilityBase *UtilityBase;
#ifdef __AROS__
struct Library *aroscbase;
#endif
struct Library *FileSysBoxBase;
struct Library *ZBase;
struct Library *SocketBase;
#ifndef __AROS__
struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
#endif

static const char vstring[];
static const char dosName[];
static const char utilityName[];
#ifdef __AROS__
static const char aroscName[];
#endif
static const char filesysboxName[];
static const char zlibName[];
static const char bsdsocketName[];
static const char amisslmasterName[];

int _start(void)
{
	struct Process *me;
	struct Message *msg = NULL;
	struct DosPacket *pkt = NULL;
	int rc = RETURN_ERROR;

	SysBase = *(struct ExecBase **)4;

	DOSBase = (struct DosLibrary *)OpenLibrary((CONST_STRPTR)dosName, 39);
	if (DOSBase == NULL)
	{
		Alert(AG_OpenLib | AO_DOSLib);
		goto cleanup;
	}

	UtilityBase = (struct UtilityBase *)OpenLibrary((CONST_STRPTR)utilityName, 39);
	if (UtilityBase == NULL)
	{
		Alert(AG_OpenLib | AO_UtilityLib);
		goto cleanup;
	}

	me = (struct Process *)FindTask(NULL);
	if (me->pr_CLI != ZERO)
	{
		/* CLI startup */
		PutStr((CONST_STRPTR)vstring);
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

#ifdef __AROS__
	aroscbase = OpenLibrary((CONST_STRPTR)aroscName, 41);
	if (aroscbase == NULL)
	{
		goto cleanup;
	}
#endif

	FileSysBoxBase = OpenLibrary((CONST_STRPTR)filesysboxName, 54);
	if (FileSysBoxBase == NULL)
	{
		goto cleanup;
	}

	ZBase = OpenLibrary((CONST_STRPTR)zlibName, 2);
	if (ZBase == NULL)
	{
		goto cleanup;
	}

	SocketBase = OpenLibrary((CONST_STRPTR)bsdsocketName, 3);
	if (SocketBase == NULL)
	{
		goto cleanup;
	}

	if (SocketBaseTags(
		SBTM_SETVAL(SBTC_BREAKMASK),     0, /* Disable CTRL-C checking in WaitSelect() */
		SBTM_SETVAL(SBTC_ERRNOLONGPTR),  (Tag)&errno,
		//SBTM_SETVAL(SBTC_HERRNOLONGPTR), &h_errno // TODO
		TAG_END))
	{
		goto cleanup;
	}

#ifndef __AROS__
	AmiSSLMasterBase = OpenLibrary((CONST_STRPTR)amisslmasterName, AMISSLMASTER_MIN_VERSION);
	if (AmiSSLMasterBase == NULL)
	{
		goto cleanup;
	}

	if (OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
		AmiSSL_UsesOpenSSLStructs, TRUE,
		AmiSSL_GetAmiSSLBase,      (Tag)&AmiSSLBase,
		AmiSSL_SocketBase,         (Tag)&SocketBase,
		AmiSSL_ErrNoPtr,           (Tag)&errno,
		TAG_END) != 0)
	{
		goto cleanup;
	}
#endif

	if (setup_malloc() == FALSE)
	{
		goto cleanup;
	}

	if (libssh2_init(0) != 0)
	{
		goto cleanup;
	}

	rc = ssh2fs_main(pkt);

	/* Set to NULL so we don't reply the packet twice */
	pkt = NULL;

cleanup:

	libssh2_exit();

	cleanup_malloc();

#ifndef __AROS__
	if (AmiSSLBase != NULL)
	{
		CloseAmiSSL();
		AmiSSLBase = NULL;
	}

	if (AmiSSLMasterBase != NULL)
	{
		CloseLibrary(AmiSSLMasterBase);
		AmiSSLMasterBase = NULL;
	}
#endif

	if (SocketBase == NULL)
	{
		CloseLibrary(SocketBase);
		SocketBase = NULL;
	}

	if (ZBase == NULL)
	{
		CloseLibrary(ZBase);
		ZBase = NULL;
	}

	if (FileSysBoxBase == NULL)
	{
		CloseLibrary(FileSysBoxBase);
		FileSysBoxBase = NULL;
	}

#ifdef __AROS__
	if (aroscbase != NULL)
	{
		CloseLibrary(aroscbase);
		aroscbase = NULL;
	}
#endif

	if (UtilityBase != NULL)
	{
		CloseLibrary((struct Library *)UtilityBase);
		UtilityBase = NULL;
	}

	if (pkt != NULL)
	{
		ReplyPkt(pkt, DOSFALSE, ERROR_INVALID_RESIDENT_LIBRARY);
		pkt = NULL;
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

/* Disable CTRL-C signal checking in libc. */
void __chkabort(void) {}

static const char USED verstag[] = VERSTAG;
static const char vstring[] = VSTRING;
static const char dosName[] = "dos.library";
static const char utilityName[] = "utility.library";
#ifdef __AROS__
static const char aroscName[] = "arosc.library";
#endif
static const char filesysboxName[] = "filesysbox.library";
static const char zlibName[] = "z.library";
static const char bsdsocketName[] = "bsdsocket.library";
static const char amisslmasterName[] = "amisslmaster.library";

