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

#include <libraries/amisslmaster.h>
#include <proto/amisslmaster.h>
#include <proto/amissl.h>

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
struct Library *AmiSSLMasterBase;
struct Library *AmiSSLBase;
//struct Library *AmiSSLExtBase;

static const TEXT vstring[];
static const TEXT dosName[];
static const TEXT utilityName[];
#ifdef __AROS__
static const TEXT aroscName[];
#endif
static const TEXT filesysboxName[];
static const TEXT zlibName[];
static const TEXT bsdsocketName[];
static const TEXT amisslmasterName[];

#ifdef __AROS__
AROS_UFH3(int, _start,
	AROS_UFHA(STRPTR, argstr, A0),
	AROS_UFHA(ULONG, arglen, D0),
	AROS_UFHA(struct ExecBase *, sysbase, A6)
)
{
	AROS_USERFUNC_INIT
#else
int _start(void)
{
#endif
	struct Process *me;
	struct Message *msg = NULL;
	struct DosPacket *pkt = NULL;
	int rc = RETURN_ERROR;

#ifdef __AROS__
	SysBase = sysbase;
#else
	SysBase = *(struct ExecBase **)4;
#endif

	DOSBase = (struct DosLibrary *)OpenLibrary(dosName, 39);
	if (DOSBase == NULL)
	{
		Alert(AG_OpenLib | AO_DOSLib);
		goto cleanup;
	}

	UtilityBase = (struct UtilityBase *)OpenLibrary(utilityName, 39);
	if (UtilityBase == NULL)
	{
		Alert(AG_OpenLib | AO_UtilityLib);
		goto cleanup;
	}

	me = (struct Process *)FindTask(NULL);
	if (me->pr_CLI != ZERO)
	{
		/* CLI startup */
		PutStr(vstring);
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
	aroscbase = OpenLibrary(aroscName, 41);
	if (aroscbase == NULL)
	{
		goto cleanup;
	}
#endif

	FileSysBoxBase = OpenLibrary(filesysboxName, 54);
	if (FileSysBoxBase == NULL)
	{
		goto cleanup;
	}

	ZBase = OpenLibrary(zlibName, 2);
	if (ZBase == NULL)
	{
		goto cleanup;
	}

	SocketBase = OpenLibrary(bsdsocketName, 3);
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

	AmiSSLMasterBase = OpenLibrary(amisslmasterName, AMISSLMASTER_MIN_VERSION);
	if (AmiSSLMasterBase == NULL)
	{
		goto cleanup;
	}

#if AMISSL_CURRENT_VERSION >= 0x12
	if (OpenAmiSSLTags(AMISSL_CURRENT_VERSION,
		AmiSSL_UsesOpenSSLStructs, TRUE,
		AmiSSL_GetAmiSSLBase,      (Tag)&AmiSSLBase,
		//AmiSSL_GetAmiSSLExtBase,   (Tag)&AmiSSLExtBase,
		AmiSSL_SocketBase,         (Tag)SocketBase,
		AmiSSL_ErrNoPtr,           (Tag)&errno,
		TAG_END) != 0)
	{
		goto cleanup;
	}
#else
	if (!InitAmiSSLMaster(AMISSL_CURRENT_VERSION, TRUE))
	{
		goto cleanup;
	}

	AmiSSLBase = OpenAmiSSL();
	if (AmiSSLBase == NULL)
	{
		goto cleanup;
	}

	if (InitAmiSSL(
		AmiSSL_SocketBase,         (Tag)SocketBase,
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

	if (AmiSSLBase != NULL)
	{
#if AMISSL_CURRENT_VERSION < 0x12
		CleanupAmiSSLA(NULL);
#endif
		CloseAmiSSL();
		AmiSSLBase = NULL;
		//AmiSSLExtBase = NULL;
	}

	if (AmiSSLMasterBase != NULL)
	{
		CloseLibrary(AmiSSLMasterBase);
		AmiSSLMasterBase = NULL;
	}

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

#ifdef __AROS__
	AROS_USERFUNC_EXIT
#endif
}

/* Disable CTRL-C signal checking in libc. */
void __chkabort(void) {}

static const TEXT USED verstag[] = VERSTAG;
static const TEXT vstring[] = VSTRING;
static const TEXT dosName[] = "dos.library";
static const TEXT utilityName[] = "utility.library";
#ifdef __AROS__
static const TEXT aroscName[] = "arosc.library";
#endif
static const TEXT filesysboxName[] = "filesysbox.library";
static const TEXT zlibName[] = "z.library";
static const TEXT bsdsocketName[] = "bsdsocket.library";
static const TEXT amisslmasterName[] = "amisslmaster.library";

