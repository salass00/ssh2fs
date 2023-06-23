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

#include <libssh2.h>
#include <libssh2_sftp.h>

#include <sys/param.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>

#include <dos/filehandler.h>
#include <libraries/bsdsocket.h>
#include <proto/bsdsocket.h>
#include <clib/debug_protos.h>

struct fuse_context *_fuse_context_;

const char Template[] =
	"HOSTADDR/A,"
	"PORT/N/K,"
	"USER/A,"
	"PASSWORD,"
	"VOLUME,"
	"READONLY/S,"
#ifdef ENABLE_HOST_KEY_CHECKING
	"NOHOSTKEYCHECK/S,"
#endif
	"NOSSHAGENT/S,"
	"KEYFILE/K,"
	"ROOTDIR/K";

enum {
	ARG_HOSTADDR,
	ARG_PORT,
	ARG_USER,
	ARG_PASSWORD,
	ARG_VOLUME,
	ARG_READONLY,
#ifdef ENABLE_HOST_KEY_CHECKING
	ARG_NOHOSTKEYCHECK,
#endif
	ARG_NOSSHAGENT,
	ARG_KEYFILE,
	ARG_ROOTDIR,
	NUM_ARGS
};

struct ssh2fs_mount_data {
	char          *device;
	struct RDArgs *rda;
#ifdef __AROS__
	IPTR           args[NUM_ARGS];
#else
	LONG           args[NUM_ARGS];
#endif
};

struct ssh2fs {
	int              socket;
	LIBSSH2_SESSION *session;
	LIBSSH2_SFTP    *sftp;
	char            *password;
	int              rdonly:1;
#ifdef ENABLE_HOST_KEY_CHECKING
	int              nohostkeycheck:1;
#endif
	int              nosshagent:1;
	char            *rootdir;
	LIBSSH2_AGENT   *agent;
	const char      *keyfile; /* For passphrase callback only */
};

struct ssh2fs *fsd;

static void ssh2fs_destroy(void *unused);

static void kbd_callback(const char *name, int name_len, const char *instruction,
	int instruction_len, int num_prompts, const LIBSSH2_USERAUTH_KBDINT_PROMPT *prompts,
	LIBSSH2_USERAUTH_KBDINT_RESPONSE *responses, void **abstract)
{
	if (num_prompts == 1)
	{
		responses[0].text   = strdup(fsd->password);
		responses[0].length = strlen(fsd->password);
	}
}

static int passphrase_callback(char *buf, int size, int rwflag, void *userdata)
{
	if (fsd->password == NULL)
	{
		fsd->password = request_password(AUTH_PUBLICKEY, fsd->keyfile);
		if (fsd->password == NULL)
		{
			if (size)
				*buf = '\0';
			return 0;
		}
	}

	strlcpy(buf, fsd->password, size);

	return strlen(buf);
}

static void *ssh2fs_init(struct fuse_conn_info *fci)
{
	struct ssh2fs_mount_data *md;
	const char               *hostname;
	const struct hostent     *hostent;
	struct in_addr            hostaddr;
	int                       port;
	struct sockaddr_in        sin;
	int                       rc;
	const char               *username;
	const char               *userauthlist;
	unsigned int              auth_pw;
	char                      homedir[1024];

	md = fuse_get_context()->private_data;

	fsd = malloc(sizeof(*fsd));
	if (fsd == NULL)
		return NULL;

	memset(fsd, 0, sizeof(*fsd));

	if (md->args[ARG_READONLY])
		fsd->rdonly = TRUE;

#ifdef ENABLE_HOST_KEY_CHECKING
	if (md->args[ARG_NOHOSTKEYCHECK])
		fsd->nohostkeycheck = TRUE;
#endif

	if (md->args[ARG_NOSSHAGENT])
		fsd->nosshagent = TRUE;

	if (md->args[ARG_ROOTDIR])
	{
		const char *patharg = (const char *)md->args[ARG_ROOTDIR];
		int         pos     = 0;
		char        pathbuf[MAXPATHLEN];
		char        namebuf[256];

		pathbuf[0] = '\0';

		do
		{
			pos = SplitName((CONST_STRPTR)patharg, '/', (STRPTR)namebuf, pos, sizeof(namebuf));

			if (namebuf[0] == '\0')
				continue;

			if (strcmp(namebuf, ".") == 0)
				continue;

			if (strcmp(namebuf, "..") == 0)
			{
				char *p;

				/* If not already at root, go up one level */
				p = strrchr(pathbuf, '/');
				if (p != NULL)
				{
					*p = '\0';
					continue;
				}
			}

			strlcat(pathbuf, "/", sizeof(pathbuf));
			strlcat(pathbuf, namebuf, sizeof(pathbuf));
		}
		while (pos != -1);

		if (pathbuf[0] != '\0')
		{
			fsd->rootdir = strdup(pathbuf);
			if (fsd->rootdir == NULL)
			{
				ssh2fs_destroy(fsd);
				return NULL;
			}
		}
	}

	fsd->socket = socket(AF_INET, SOCK_STREAM, 0);
	if (fsd->socket < 0)
	{
		KPutS((CONST_STRPTR)"[ssh2fs] Failed to create socket!\n");
		ssh2fs_destroy(fsd);
		return NULL;
	}

	hostname = (const char *)md->args[ARG_HOSTADDR];
	hostent  = gethostbyname((APTR)hostname);
	if (hostent == NULL)
	{
		KPrintF((CONST_STRPTR)"[ssh2fs] Failed to resolve host address, '%s'!\n", hostname);
		//KPrintF((CONST_STRPTR)"[ssh2fs] h_errno: %d (%s)\n", h_errno, hstrerror(h_errno));
		ssh2fs_destroy(fsd);
		return NULL;
	}

	if (hostent->h_addrtype != AF_INET)
	{
		KPutS((CONST_STRPTR)"[ssh2fs] Only IPv4 addresses are supported!\n");
		ssh2fs_destroy(fsd);
		return NULL;
	}

	memcpy(&hostaddr, hostent->h_addr_list[0], sizeof(struct in_addr));

	port = 22;

	if (md->args[ARG_PORT])
	{
		port = *(LONG *)md->args[ARG_PORT];
	}

	KPrintF((CONST_STRPTR)"[ssh2fs] host address: %s port: %ld\n", hostname, port);

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_port   = htons(port);
	sin.sin_addr   = hostaddr;

	if (connect(fsd->socket, (struct sockaddr *)&sin, sizeof(sin)) != 0)
	{
		KPutS((CONST_STRPTR)"[ssh2fs] Failed to connect!\n");
		//KPrintF((CONST_STRPTR)"[ssh2fs] h_errno: %d (%s)\n", h_errno, hstrerror(h_errno));
		ssh2fs_destroy(fsd);
		return NULL;
	}

	fsd->session = libssh2_session_init();
	if (fsd->session == NULL)
	{
		KPutS((CONST_STRPTR)"[ssh2fs] Unable to init SSH session!\n");
		ssh2fs_destroy(fsd);
		return NULL;
	}

	//libssh2_trace(fsd->session, LIBSSH2_TRACE_KEX);

	rc = libssh2_session_handshake(fsd->session, fsd->socket);
	if (rc < 0)
	{
		KPrintF((CONST_STRPTR)"[ssh2fs] Failure establishing SSH session: %ld\n", rc);
		ssh2fs_destroy(fsd);
		return NULL;
	}

	/* Get HOME directory */
	if (GetVar((CONST_STRPTR)"HOME", (STRPTR)homedir, sizeof(homedir), 0) <= 0)
	{
		strcpy(homedir, "HOME:");
	}

#ifdef ENABLE_HOST_KEY_CHECKING
	if (!fsd->nohostkeycheck) {
		LIBSSH2_KNOWNHOSTS *kh;
		char                khfile[1024];
		const char         *remotekey;
		size_t              keylen;
		int                 keytype;

		kh = libssh2_knownhost_init(fsd->session);
		if (kh == NULL)
		{
			ssh2fs_destroy(fsd);
			return NULL;
		}

		strlcpy(khfile, homedir, sizeof(khfile));
		AddPart(khfile, ".ssh/known_hosts", sizeof(khfile));

		rc = libssh2_knownhost_readfile(kh, khfile, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
		if (rc < 0 && !(rc == LIBSSH2_ERROR_FILE && errno == ENOENT)) {
			libssh2_knownhost_free(kh);
			ssh2fs_destroy(fsd);
			return NULL;
		}

		remotekey = libssh2_session_hostkey(fsd->session, &keylen, &keytype);
		if (remotekey != NULL)
		{
			struct libssh2_knownhost *host;
			int                       keybit;

			if (keytype == LIBSSH2_HOSTKEY_TYPE_RSA)
				keybit = LIBSSH2_KNOWNHOST_KEY_SSHRSA;
			else
				keybit = LIBSSH2_KNOWNHOST_KEY_SSHDSS;

			rc = libssh2_knownhost_checkp(kh, hostname, port, remotekey, keylen,
				LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW | keybit,
				&host);
			if (rc != LIBSSH2_KNOWNHOST_CHECK_MATCH) {
				switch (rc) {
					case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
						/* Fingerprint does not match! */
						break;

					case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
						/* Not in list */
						break;

					case LIBSSH2_KNOWNHOST_CHECK_FAILURE:
						libssh2_knownhost_free(kh);
						ssh2fs_destroy(fsd);
						return NULL;
				}
			}
		} else {
			/* No host key! */
		}

		libssh2_knownhost_free(kh);
	}
#endif

	username = (const char *)md->args[ARG_USER];

	auth_pw = 0;

	userauthlist = libssh2_userauth_list(fsd->session, username, strlen(username));
	if (strstr(userauthlist, "password") != NULL)
	{
		auth_pw |= AUTH_PASSWORD;
	}
	if (strstr(userauthlist, "keyboard-interactive") != NULL)
	{
		auth_pw |= AUTH_KEYBOARD_INTERACTIVE;
	}
	if (strstr(userauthlist, "publickey") != NULL)
	{
		auth_pw |= AUTH_PUBLICKEY;
	}

	if (md->args[ARG_KEYFILE])
	{
		/* Force public key authentication if the KEYFILE argument is specified
		 * and this method is supported by the SSH server.
		 */
		if (auth_pw & AUTH_PUBLICKEY)
		{
			auth_pw = AUTH_PUBLICKEY;
		}
	}

	if (auth_pw == 0)
	{
		KPutS((CONST_STRPTR)"[ssh2fs] No supported authentication methods found!\n");
		ssh2fs_destroy(fsd);
		return NULL;
	}

	if (md->args[ARG_PASSWORD])
	{
		fsd->password = strdup((const char *)md->args[ARG_PASSWORD]);
	}

	if (auth_pw & AUTH_PASSWORD)
	{
		if (fsd->password == NULL)
		{
			fsd->password = request_password(AUTH_PASSWORD, username, hostname);
			if (fsd->password == NULL)
			{
				ssh2fs_destroy(fsd);
				return NULL;
			}
		}

		if (libssh2_userauth_password(fsd->session, username, fsd->password))
		{
			KPutS((CONST_STRPTR)"[ssh2fs] Authentication by password failed!\n");
			ssh2fs_destroy(fsd);
			return NULL;
		}
	}
	else if (auth_pw & AUTH_KEYBOARD_INTERACTIVE)
	{
		if (fsd->password == NULL)
		{
			fsd->password = request_password(AUTH_KEYBOARD_INTERACTIVE, username, hostname);
			if (fsd->password == NULL)
			{
				ssh2fs_destroy(fsd);
				return NULL;
			}
		}

		if (libssh2_userauth_keyboard_interactive(fsd->session, username, &kbd_callback))
		{
			KPutS((CONST_STRPTR)"[ssh2fs] Authentication by keyboard-interactive failed!\n");
			ssh2fs_destroy(fsd);
			return NULL;
		}
	}
	else
	{
		BOOL authenticated = FALSE;

		if (!fsd->nosshagent)
		{
			fsd->agent = libssh2_agent_init(fsd->session);
			if (fsd->agent == NULL)
			{
				KPutS((CONST_STRPTR)"[ssh2fs] Failure initializing ssh-agent support!\n");
			}
			else
			{
				rc = libssh2_agent_connect(fsd->agent);
				if (rc < 0)
				{
					KPutS((CONST_STRPTR)"[ssh2fs] Failure connecting to ssh-agent!\n");
				}
				else
				{
					struct libssh2_agent_publickey *identity;
					struct libssh2_agent_publickey *prev_identity = NULL;

					if (libssh2_agent_list_identities(fsd->agent))
					{
						KPutS((CONST_STRPTR)"[ssh2fs] Failure requesting identities from ssh-agent!\n");
						ssh2fs_destroy(fsd);
						return NULL;
					}
					while (TRUE)
					{
						rc = libssh2_agent_get_identity(fsd->agent, &identity, prev_identity);
						if (rc == 1)
							break;
						if (rc < 0)
						{
							KPutS((CONST_STRPTR)"[ssh2fs] Failure obtaining identity from ssh-agent support!\n");
							ssh2fs_destroy(fsd);
							return NULL;
						}

						if (libssh2_agent_userauth(fsd->agent, username, identity))
						{
							KPrintF((CONST_STRPTR)"[ssh2fs] Authentication with username %s and public key %s failed!\n",
								username, identity->comment);
						}
						else
						{
							KPrintF((CONST_STRPTR)"[ssh2fs] Authentication with username %s and public key %s succeeded!\n",
								username, identity->comment);
							authenticated = TRUE;
							break;
						}

						prev_identity = identity;
					}
				}
			}
		}

		if (!authenticated)
		{
			char keyfile1[1024];
			char keyfile2[1024];

			if (fsd->agent != NULL)
			{
				libssh2_agent_disconnect(fsd->agent);
				libssh2_agent_free(fsd->agent);
				fsd->agent = NULL;
			}

			if (md->args[ARG_KEYFILE])
			{
				strlcpy(keyfile1, (const char *)md->args[ARG_KEYFILE], sizeof(keyfile1));
				strlcat(keyfile1, ".pub", sizeof(keyfile1));
				strlcpy(keyfile2, (const char *)md->args[ARG_KEYFILE], sizeof(keyfile2));
			}
			else
			{
				strlcpy(keyfile1, homedir, sizeof(keyfile1));
				strlcpy(keyfile2, homedir, sizeof(keyfile2));

				AddPart((STRPTR)keyfile1, (CONST_STRPTR)".ssh/id_rsa.pub", sizeof(keyfile1));
				AddPart((STRPTR)keyfile2, (CONST_STRPTR)".ssh/id_rsa", sizeof(keyfile2));
			}

			fsd->keyfile = keyfile2;
			libssh2_passphrase_callback_set(fsd->session, &passphrase_callback);

			if (libssh2_userauth_publickey_fromfile(fsd->session, username, keyfile1, keyfile2, NULL/*fsd->password*/))
			{
				KPutS((CONST_STRPTR)"[ssh2fs] Authentication by public key failed!\n");
				ssh2fs_destroy(fsd);
				return NULL;
			}
		}
	}

	fsd->sftp = libssh2_sftp_init(fsd->session);
	if (fsd->sftp == NULL)
	{
		KPutS((CONST_STRPTR)"[ssh2fs] Unable to init SFTP session!\n");
		ssh2fs_destroy(fsd);
		return NULL;
	}

	libssh2_session_set_blocking(fsd->session, 1);

	if (md->args[ARG_VOLUME])
	{
		strlcpy(fci->volume_name, (const char *)md->args[ARG_VOLUME], CONN_VOLUME_NAME_BYTES);
	}
	else
	{
		snprintf(fci->volume_name, CONN_VOLUME_NAME_BYTES, "%s@%s",
			username, hostname);
	}

	return fsd;
}

static void ssh2fs_destroy(void *unused)
{
	if (fsd == NULL)
		return;

	if (fsd->sftp != NULL)
	{
		libssh2_sftp_shutdown(fsd->sftp);
		fsd->sftp = NULL;
	}

	if (fsd->agent != NULL)
	{
		libssh2_agent_disconnect(fsd->agent);
		libssh2_agent_free(fsd->agent);
		fsd->agent = NULL;
	}

	if (fsd->session != NULL)
	{
		libssh2_session_disconnect(fsd->session, "Normal Shutdown, Thank you for playing");
		libssh2_session_free(fsd->session);
		fsd->session = NULL;
	}

	if (fsd->password != NULL)
	{
		bzero(fsd->password, strlen(fsd->password));
		free(fsd->password);
		fsd->password = NULL;
	}

	if (fsd->socket >= 0)
	{
		CloseSocket(fsd->socket);
		fsd->socket = -1;
	}

	if (fsd->rootdir != NULL)
	{
		free(fsd->rootdir);
		fsd->rootdir = NULL;
	}

	free(fsd);
	fsd = NULL;
}

static int ssh2fs_convert_error(int rc)
{
	switch (rc)
	{
		case LIBSSH2_ERROR_ALLOC:
			return ENOMEM;

		case LIBSSH2_ERROR_SFTP_PROTOCOL:
			switch (libssh2_sftp_last_error(fsd->sftp))
			{
				case LIBSSH2_FX_NO_SUCH_FILE:
				case LIBSSH2_FX_NO_SUCH_PATH:
					return ENOENT;

				case LIBSSH2_FX_PERMISSION_DENIED:
					return EACCES;

				case LIBSSH2_FX_OP_UNSUPPORTED:
					return EOPNOTSUPP;

				case LIBSSH2_FX_INVALID_HANDLE:
					return EINVAL;

				case LIBSSH2_FX_FILE_ALREADY_EXISTS:
					return EEXIST;

				case LIBSSH2_FX_WRITE_PROTECT:
					return EROFS;

				case LIBSSH2_FX_NO_SPACE_ON_FILESYSTEM:
					return ENOSPC;

				case LIBSSH2_FX_DIR_NOT_EMPTY:
					return ENOTEMPTY;

				case LIBSSH2_FX_NOT_A_DIRECTORY:
					return ENOTDIR;

				default:
					KPrintF((CONST_STRPTR)"[ssh2fs] libssh2 sftp error: %ld\n", libssh2_sftp_last_error(fsd->sftp));
					/* Used as a generic error */
					return EIO;
			}
			break;

		case LIBSSH2_ERROR_INVAL:
			return EINVAL;

		case LIBSSH2_ERROR_EAGAIN:
			return EAGAIN;

		default:
			KPrintF((CONST_STRPTR)"[ssh2fs] libssh2 error: %ld\n", rc);
			/* Used as a generic error */
			return EIO;
	}
}

static int ssh2fs_statfs(const char *path, struct statvfs *sfs)
{
	LIBSSH2_SFTP_STATVFS sftp_sfs;
	int                  rc;
	char                 pathbuf[MAXPATHLEN];
	uint32_t             frsize;
	uint64_t             blocks, bfree, bavail;

	if (fsd == NULL)
		return -ENODEV;

	if (path == NULL || path[0] == '\0')
		path = "/";

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	rc = libssh2_sftp_statvfs(fsd->sftp, path, strlen(path), &sftp_sfs);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	frsize = sftp_sfs.f_frsize;
	blocks = sftp_sfs.f_blocks;
	bfree  = sftp_sfs.f_bfree;
	bavail = sftp_sfs.f_bavail;
	while (blocks > INT32_MAX)
	{
		frsize <<= 1;
		blocks >>= 1;
		bfree  >>= 1;
		bavail >>= 1;
	}

	sfs->f_bsize  = sftp_sfs.f_bsize;
	sfs->f_frsize = frsize;
	sfs->f_blocks = blocks;
	sfs->f_bfree  = bfree;
	sfs->f_bavail = bavail;
	sfs->f_files  = sftp_sfs.f_files;
	sfs->f_ffree  = sftp_sfs.f_ffree;
	sfs->f_favail = sftp_sfs.f_favail;
	sfs->f_fsid   = sftp_sfs.f_fsid;

	sfs->f_flag = ST_CASE_SENSITIVE;

	if ((sftp_sfs.f_flag & LIBSSH2_SFTP_ST_RDONLY) != 0 || fsd->rdonly)
		sfs->f_flag |= ST_RDONLY;

	if ((sftp_sfs.f_flag & LIBSSH2_SFTP_ST_NOSUID) != 0)
		sfs->f_flag |= ST_NOSUID;

	sfs->f_namemax = 255;

	return 0;
}

static void ssh2fs_fillstat(struct fbx_stat *stbuf, const LIBSSH2_SFTP_ATTRIBUTES *attrs)
{
	memset(stbuf, 0, sizeof(*stbuf));

	//KPrintF((CONST_STRPTR)"[ssh2fs] attrs->flags: 0x%08lx\n", attrs->flags);

	if ((attrs->flags & LIBSSH2_SFTP_ATTR_SIZE) != 0)
	{
		stbuf->st_size = attrs->filesize;
	}

	if ((attrs->flags & LIBSSH2_SFTP_ATTR_UIDGID) != 0)
	{
		stbuf->st_uid = attrs->uid;
		stbuf->st_gid = attrs->gid;
	}

	if ((attrs->flags & LIBSSH2_SFTP_ATTR_PERMISSIONS) != 0)
	{
		stbuf->st_mode = attrs->permissions;
	}

	if ((attrs->flags & LIBSSH2_SFTP_ATTR_ACMODTIME) != 0)
	{
		stbuf->st_atime = attrs->atime;
		stbuf->st_ctime = attrs->mtime;
		stbuf->st_mtime = attrs->mtime;
	}
}

static int ssh2fs_getattr(const char *path, struct fbx_stat *stbuf)
{
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	int                     rc;
	char                    pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	rc = libssh2_sftp_lstat(fsd->sftp, path, &attrs);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	ssh2fs_fillstat(stbuf, &attrs);

	return 0;
}

static int ssh2fs_fgetattr(const char *path, struct fbx_stat *stbuf,
	struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE     *handle;
	LIBSSH2_SFTP_ATTRIBUTES  attrs;
	int                      rc;

	if (fsd == NULL)
		return -ENODEV;

	handle = (LIBSSH2_SFTP_HANDLE *)(size_t)fi->fh;
	if (handle == NULL)
		return -EINVAL;

	rc = libssh2_sftp_fstat(handle, &attrs);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	ssh2fs_fillstat(stbuf, &attrs);

	return 0;
}

static int ssh2fs_mkdir(const char *path, mode_t mode)
{
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	rc = libssh2_sftp_mkdir(fsd->sftp, path, mode);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_opendir(const char *path, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE *handle;
	int                  rc;
	int                  result;
	char                 pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	handle = libssh2_sftp_opendir(fsd->sftp, path);
	if (handle != NULL)
	{
		fi->fh = (uint64_t)(size_t)handle;
		return 0;
	}
	else
	{
		rc = libssh2_session_last_errno(fsd->session);
		result = -ssh2fs_convert_error(rc);
	}

	return result;
}

static int ssh2fs_releasedir(const char *path, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE *handle;

	if (fsd == NULL)
		return -ENODEV;

	handle = (LIBSSH2_SFTP_HANDLE *)(size_t)fi->fh;
	if (handle == NULL)
		return -EINVAL;

	libssh2_sftp_closedir(handle);
	fi->fh = (uint64_t)(size_t)NULL;

	return 0;
}

static int ssh2fs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
	fbx_off_t offset, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE     *handle;
	char                     namebuf[256];
	LIBSSH2_SFTP_ATTRIBUTES  attrs;
	struct fbx_stat          stbuf;
	int                      rc;

	if (fsd == NULL)
		return -ENODEV;

	if (fi == NULL)
		return -EINVAL;

	handle = (LIBSSH2_SFTP_HANDLE *)(size_t)fi->fh;
	if (handle == NULL)
		return -EINVAL;

	while ((rc = libssh2_sftp_readdir(handle, namebuf, sizeof(namebuf), &attrs)) > 0)
	{
		ssh2fs_fillstat(&stbuf, &attrs);
		filler(buffer, namebuf, &stbuf, 0);
	}

	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_open(const char *path, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE *handle;
	unsigned long        flags;
	int                  rc;
	int                  result;
	char                 pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	flags = LIBSSH2_FXF_READ;

	if (!fsd->rdonly)
		flags |= LIBSSH2_FXF_WRITE;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	for (;;)
	{
		handle = libssh2_sftp_open(fsd->sftp, path, flags, 0);
		if (handle != NULL)
		{
			fi->fh = (uint64_t)(size_t)handle;
			return 0;
		}
		else
		{
			rc = libssh2_session_last_errno(fsd->session);

			if (rc == LIBSSH2_ERROR_SFTP_PROTOCOL &&
			    libssh2_sftp_last_error(fsd->sftp) == LIBSSH2_FX_PERMISSION_DENIED &&
			    (flags & LIBSSH2_FXF_WRITE) != 0)
			{
				/* If error was permission denied and read/write access was requested
				 * try again with only read access.
				 */
				flags &= ~LIBSSH2_FXF_WRITE;
				continue;
			}

			result = -ssh2fs_convert_error(rc);
			break;
		}
	}

	return result;
}

static int ssh2fs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE *handle;
	unsigned long        flags;
	int                  rc;
	int                  result;
	char                 pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	flags = LIBSSH2_FXF_CREAT | LIBSSH2_FXF_EXCL | LIBSSH2_FXF_READ | LIBSSH2_FXF_WRITE;

	handle = libssh2_sftp_open(fsd->sftp, path, flags, mode);
	if (handle != NULL)
	{
		fi->fh = (uint64_t)(size_t)handle;
		return 0;
	}
	else
	{
		rc = libssh2_session_last_errno(fsd->session);
		result = -ssh2fs_convert_error(rc);
	}

	return result;
}

static int ssh2fs_release(const char *path, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE *handle;

	if (fsd == NULL)
		return -ENODEV;

	handle = (LIBSSH2_SFTP_HANDLE *)(size_t)fi->fh;
	if (handle == NULL)
		return -EINVAL;

	libssh2_sftp_close(handle);
	fi->fh = (uint64_t)(size_t)NULL;

	return 0;
}

static int ssh2fs_read(const char *path, char *buffer, size_t size,
	fbx_off_t offset, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE *handle;
	ssize_t              rc = 0;
	int                  result;

	if (fsd == NULL)
		return -ENODEV;

	handle = (LIBSSH2_SFTP_HANDLE *)(size_t)fi->fh;
	if (handle == NULL)
		return -EINVAL;

	libssh2_sftp_seek64(handle, offset);

	result = 0;

	while (size > 0)
	{
		rc = libssh2_sftp_read(handle, buffer, size);
		if (rc <= 0)
			break;

		result += rc;
		buffer += rc;
		size   -= rc;
	}

	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return result;
}

static int ssh2fs_write(const char *path, const char *buffer, size_t size,
	fbx_off_t offset, struct fuse_file_info *fi)
{
	LIBSSH2_SFTP_HANDLE *handle;
	ssize_t              rc = 0;
	int                  result;

	if (fsd == NULL)
		return -ENODEV;

	handle = (LIBSSH2_SFTP_HANDLE *)(size_t)fi->fh;
	if (handle == NULL)
		return -EINVAL;

	if (fsd->rdonly)
		return -EROFS;

	libssh2_sftp_seek64(handle, offset);

	result = 0;

	while (size > 0)
	{
		rc = libssh2_sftp_write(handle, buffer, size);
		if (rc < 0)
			break;

		result += rc;
		buffer += rc;
		size   -= rc;
	}

	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return result;
}

static int ssh2fs_truncate(const char *path, fbx_off_t size)
{
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	int                     rc;
	char                    pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	attrs.flags    = LIBSSH2_SFTP_ATTR_SIZE;
	attrs.filesize = size;

	rc = libssh2_sftp_setstat(fsd->sftp, path, &attrs);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_utimens(const char *path, const struct timespec tv[2])
{
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	int                     rc;
	char                    pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	attrs.flags = LIBSSH2_SFTP_ATTR_ACMODTIME;
	attrs.atime = tv[0].tv_sec;
	attrs.mtime = tv[1].tv_sec;

	rc = libssh2_sftp_setstat(fsd->sftp, path, &attrs);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_unlink(const char *path)
{
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	rc = libssh2_sftp_unlink(fsd->sftp, path);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_rmdir(const char *path)
{
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	rc = libssh2_sftp_rmdir(fsd->sftp, path);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_readlink(const char *path, char *buffer, size_t size)
{
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	rc = libssh2_sftp_readlink(fsd->sftp, path, buffer, size);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

#if 0
static int ssh2fs_symlink(const char *target, const char *path)
{
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	rc = libssh2_sftp_symlink(fsd->sftp, path, (char *)target);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}
#endif

static int ssh2fs_rename(const char *old_path, const char *new_path)
{
	unsigned long flags;
	int           rc;
	char          old_pathbuf[MAXPATHLEN];
	char          new_pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(old_pathbuf, fsd->rootdir, sizeof(old_pathbuf));
		strlcat(old_pathbuf, old_path, sizeof(old_pathbuf));
		old_path = old_pathbuf;
		strlcpy(new_pathbuf, fsd->rootdir, sizeof(new_pathbuf));
		strlcat(new_pathbuf, new_path, sizeof(new_pathbuf));
		new_path = new_pathbuf;
	}

	flags = LIBSSH2_SFTP_RENAME_ATOMIC | LIBSSH2_SFTP_RENAME_NATIVE;

	rc = libssh2_sftp_rename_ex(fsd->sftp, old_path, strlen(old_path),
		new_path, strlen(new_path), flags);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_chmod(const char *path, mode_t mode)
{
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	int                     rc;
	char                    pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	attrs.flags       = LIBSSH2_SFTP_ATTR_PERMISSIONS;
	attrs.permissions = mode;

	rc = libssh2_sftp_setstat(fsd->sftp, path, &attrs);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_chown(const char *path, uid_t uid, gid_t gid)
{
	LIBSSH2_SFTP_ATTRIBUTES attrs;
	int                     rc;
	char                    pathbuf[MAXPATHLEN];

	if (fsd == NULL)
		return -ENODEV;

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL) {
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	attrs.flags = LIBSSH2_SFTP_ATTR_UIDGID;
	attrs.uid   = uid;
	attrs.gid   = gid;

	rc = libssh2_sftp_setstat(fsd->sftp, path, &attrs);
	if (rc < 0)
	{
		return -ssh2fs_convert_error(rc);
	}

	return 0;
}

static int ssh2fs_relabel(const char *label)
{
	/* Nothing to do here */
	return 0;
}

static struct fuse_operations ssh2fs_ops =
{
	.init       = ssh2fs_init,
	.destroy    = ssh2fs_destroy,
	.statfs     = ssh2fs_statfs,
	.getattr    = ssh2fs_getattr,
	.fgetattr   = ssh2fs_fgetattr,
	.mkdir      = ssh2fs_mkdir,
	.opendir    = ssh2fs_opendir,
	.releasedir = ssh2fs_releasedir,
	.readdir    = ssh2fs_readdir,
	.open       = ssh2fs_open,
	.create     = ssh2fs_create,
	.release    = ssh2fs_release,
	.read       = ssh2fs_read,
	.write      = ssh2fs_write,
	.truncate   = ssh2fs_truncate,
	.utimens    = ssh2fs_utimens,
	.unlink     = ssh2fs_unlink,
	.rmdir      = ssh2fs_rmdir,
	.readlink   = ssh2fs_readlink,
	/* .symlink    = ssh2fs_symlink, */
	.rename     = ssh2fs_rename,
	.chmod      = ssh2fs_chmod,
	.chown      = ssh2fs_chown,
	.relabel    = ssh2fs_relabel
};

static void remove_double_quotes(char *argstr)
{
	char *start, *end;
	int   len;

	start = argstr;
	end   = start + strlen(start);

	/* Strip leading white space characters */
	while (isspace((unsigned char)start[0]))
	{
		start++;
	}

	/* Strip trailing white space characters */
	while (end > start && isspace((unsigned char)end[-1]))
	{
		end--;
	}

	/* Remove opening quote ... */
	if (start[0] == '"')
	{
		start++;

		/* ... and closing quote */
		if (end > start && end[-1] == '"')
		{
			end--;
		}
	}

	/* Move to start of buffer and NUL-terminate */
	len = end - start;
	memmove(argstr, start, len);
	argstr[len] = '\0';
}

#ifdef __AROS__
static struct RDArgs *read_startup_args(CONST_STRPTR template, IPTR *args, const char *startup)
#else
static struct RDArgs *read_startup_args(CONST_STRPTR template, LONG *args, const char *startup)
#endif
{
	char          *argstr;
	struct RDArgs *rda, *result = NULL;

	argstr = malloc(strlen(startup) + 2);
	if (argstr == NULL)
	{
		SetIoErr(ERROR_NO_FREE_STORE);
		return NULL;
	}

	//KPrintF((CONST_STRPTR)"[ssh2fs] startup: '%s'\n", startup);
	strcpy(argstr, startup);
	remove_double_quotes(argstr);
	//KPrintF((CONST_STRPTR)"[ssh2fs] argstr: '%s'\n", argstr);
	strcat(argstr, "\n");

	rda = AllocDosObject(DOS_RDARGS, NULL);
	if (rda != NULL)
	{
		rda->RDA_Source.CS_Buffer = (STRPTR)argstr;
		rda->RDA_Source.CS_Length = strlen(argstr);
		rda->RDA_Flags            = RDAF_NOPROMPT;

		result = ReadArgs(template, (APTR)args, rda);
		if (result == NULL)
		{
			FreeDosObject(DOS_RDARGS, rda);
		}
	}

	free(argstr);
	return result;
}

static void free_startup_args(struct RDArgs *rda)
{
	if (rda != NULL)
	{
		FreeArgs(rda);
		FreeDosObject(DOS_RDARGS, rda);
	}
}

int ssh2fs_main(struct DosPacket *pkt)
{
	struct ssh2fs_mount_data  md;
	struct DeviceNode        *devnode;
	const char               *device;
	const char               *startup;
	struct FbxFS             *fs = NULL;
	int                       error;
	int                       rc = RETURN_ERROR;

	memset(&md, 0, sizeof(md));

	devnode = (struct DeviceNode *)BADDR(pkt->dp_Arg3);

#ifdef __AROS__
	device  = (const char *)AROS_BSTR_ADDR(devnode->dn_Name);
	startup = (const char *)AROS_BSTR_ADDR(devnode->dn_Startup);
#else
	device  = (const char *)BADDR(devnode->dn_Name) + 1;
	startup = (const char *)BADDR(devnode->dn_Startup) + 1;
#endif

	devnode->dn_Startup = ZERO;

	md.device = strdup(device);
	if (md.device == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto cleanup;
	}

	md.rda = read_startup_args((CONST_STRPTR)Template, md.args, startup);
	if (md.rda == NULL)
	{
		error = IoErr();
		goto cleanup;
	}

	struct TagItem fs_tags[] = {
		{ FBXT_FSFLAGS,     FBXF_ENABLE_UTF8_NAMES | FBXF_USE_FILL_DIR_STAT },
		{ FBXT_DOSTYPE,     ID_SSH2_DISK                                    },
		{ FBXT_GET_CONTEXT, (IPTR)&_fuse_context_                           },
		{ TAG_END,          0                                               }
	};

	fs = FbxSetupFS(pkt->dp_Link, fs_tags, &ssh2fs_ops, sizeof(ssh2fs_ops), &md);

	/* Set to NULL so we don't reply the message twice */
	pkt = NULL;

	if (fs != NULL)
	{
		FbxEventLoop(fs);

		rc = RETURN_OK;
	}

cleanup:

	if (fs != NULL)
	{
		FbxCleanupFS(fs);
		fs = NULL;
	}

	if (pkt != NULL)
	{
		ReplyPkt(pkt, DOSFALSE, error);
		pkt = NULL;
	}

	if (md.rda != NULL)
	{
		free_startup_args(md.rda);
		md.rda = NULL;
	}

	if (md.device != NULL)
	{
		free(md.device);
		md.device = NULL;
	}

	return rc;
}

