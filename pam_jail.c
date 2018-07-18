// SPDX-License-Identifier: GPL-2.0
// Copyright © 2007-2018 ANSSI. All Rights Reserved.
/* 
 *  pam_jail.c - pam module to automatically jail a user in vserver 
 *               context.
 *  Copyright (C) 2007 SGDN/DCSSI
 *  Author: Vincent Strubel <clipos@ssi.gouv.fr>
 *
 *  Largely based on pam_chroot, which is Copyrighted by its various
 *  authors, see CREDITS and LICENSE files.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License version
 *  2 as published by the Free Software Foundation.
 *
 */


#define _GNU_SOURCE
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>

#include <clip/clip-vserver.h>

#define  PAM_SM_AUTH
#define  PAM_SM_ACCOUNT
#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/_pam_macros.h>

#define CONFIG	"/etc/security/pam_jail.conf"
#define LINELEN	1024		/* max length (bytes) of line in config file */
#define MAX_GROUPS	64	/* maximum number of groups we handle */

/* defines for flags */
#define _PAM_OPTS_NOOPTS	0x0000
#define _PAM_OPTS_DEBUG		0x0001
#define _PAM_OPTS_NOJAIL	0x0002
#define _PAM_OPTS_NOTFOUNDFAILS	0x0004
#define _PAM_OPTS_PROXY		0x0008

/* defines for (internal) return values */
#define _PAM_JAIL_INTERNALERR	-2
#define _PAM_JAIL_SYSERR	-1
#define _PAM_JAIL_OK	0
#define _PAM_JAIL_GROUPNOTFOUND	1
#define _PAM_JAIL_INCOMPLETE	2

typedef uint32_t xid_t;

struct _pam_opts {
	int16_t flags;		/* combined option flags */
	xid_t	xid;		/* xid of jail to enter */
	char* module;		/* module currently being processed */
};

static void 
_pam_log(int err, const char *format, ...) 
{
	va_list args;

	va_start(args, format);
	openlog("pam_jail", LOG_PID, LOG_AUTHPRIV);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

#define _PAM_JAIL_ERROR(fmt, args...) _pam_log(LOG_ERR, "%s: " fmt, \
					__FUNCTION__, ## args)

#define _PAM_JAIL_DEBUG(opts, fmt, args...) do {\
	if ((opts)->flags & _PAM_OPTS_DEBUG) \
		_pam_log(LOG_INFO, "%s: " fmt, __FUNCTION__, ## args); \
} while (0)

/* initialize opts to a standard known state */
static int 
_pam_opts_init(struct _pam_opts* opts) 
{
	if(!opts) {
		_PAM_JAIL_ERROR("NULL opts pointer");
		return _PAM_JAIL_INTERNALERR;
	}

	opts->flags = _PAM_OPTS_NOOPTS;
	opts->xid = 0;

	return _PAM_JAIL_OK;
}

/* configure opts per the passed flags and cmd line args */
static 
int _pam_opts_config(struct _pam_opts* opts, int flags,
		int argc, const char** argv)
{
	int i;

	if(!opts) {
		_PAM_JAIL_ERROR("NULL opts pointer");
		return _PAM_JAIL_INTERNALERR;
	}

	if((flags & PAM_DISALLOW_NULL_AUTHTOK) &&
			(!strcmp(opts->module, "auth") 
			 || !strcmp(opts->module, "account")))
	{
		opts->flags = opts->flags | _PAM_OPTS_NOTFOUNDFAILS;
	}

	/* parse command line args */
	for(i = 0; i < argc; i++) {
		if(!strcmp(argv[i], "debug")) {
			opts->flags = opts->flags | _PAM_OPTS_DEBUG;
		} else if(!strcmp(argv[i], "no_jail")) {
			opts->flags = opts->flags | _PAM_OPTS_NOJAIL;
		} else if(!strcmp(argv[i], "not_found_fails")) {
			opts->flags = opts->flags | _PAM_OPTS_NOTFOUNDFAILS;
		} else if(!strcmp(argv[i], "proxy")) {
			opts->flags = opts->flags | _PAM_OPTS_PROXY;
		} else {
			_PAM_JAIL_ERROR("unrecognized config option: \"%s\"", argv[i]);
		}
	}
	_PAM_JAIL_DEBUG(opts, "Parsed flags 0x%hx\n", opts->flags);

	return _PAM_JAIL_OK;
}

/* free the allocated memory of a struct _pam_opts */
static int 
_pam_opts_free(struct _pam_opts* opts) 
{
	if(!opts) {
		_PAM_JAIL_ERROR("NULL opts pointer");
	}

	return _PAM_JAIL_OK;
}

struct jail_descr {
	char *name;
	xid_t xid;
};

#define _free_descr(descr) do {\
	if ((descr)->name) free((descr)->name); \
	(descr)->name = NULL; \
	(descr)->xid = 0; \
} while (0)
	

typedef enum {
	_PAM_READ_OK,
	_PAM_READ_NOK,
	_PAM_READ_NULL,
	_PAM_READ_END
} read_retval_t;

static read_retval_t
_pam_read_jaildescr(FILE *conf, struct jail_descr *descr)
{
	char conf_line[LINELEN];
	char *ptr, *name;
	unsigned long xid;

	ptr = fgets(conf_line, LINELEN, conf);
	if (!ptr)
		return _PAM_READ_END;

	if ((ptr = strchr(conf_line, '#')))
		*ptr = '\0';
	
	if ((ptr = strchr(conf_line, '\n')))
		*ptr = '\0';

	if (!conf_line[0])
		return _PAM_READ_NULL;

	
	ptr = conf_line;
	name = strsep(&ptr, " \t");
	if (!name)
		return _PAM_READ_NOK; /* WTF ? */

	xid = strtoul(ptr, NULL, 0);
	if (errno) {
		_PAM_JAIL_ERROR("numeric conversion error on %s\n", ptr);
		return _PAM_READ_NOK;
	}
	if (xid > UINT_MAX) {
		_PAM_JAIL_ERROR("xid too big %s\n", ptr);
		return _PAM_READ_NOK;
	}

	descr->name = x_strdup(name);
	if (!descr->name) {
		_PAM_JAIL_ERROR("strdup: %s", strerror(errno));
		return _PAM_READ_NOK;
	}

	descr->xid = (uint32_t) xid;

	return _PAM_READ_OK;
}

/* Return 1 on match, 0 if no match, -1 on error */
static inline int
_pam_checkgroup(const char *name, gid_t *groups, size_t len)
{
	struct group *grp;
	size_t i;

	grp = getgrnam(name);
	if (!grp) {
		_PAM_JAIL_ERROR("getgrnam (%s) error: %s", name, strerror(errno));
		return -1;
	}
	
	for (i = 0; i < len; ++i) {
		if (groups[i] == grp->gr_gid)
			return 1;
	}

	return 0;
}

static int 
_pam_get_jail(const char *user, struct _pam_opts *opts)
{
	gid_t groups[MAX_GROUPS];
	struct jail_descr descr;
	struct passwd *pwd;
	int ret;
	read_retval_t readret;
	FILE *conf;
	int ngroups = MAX_GROUPS;

	memset(&descr, 0, sizeof(descr));
	pwd = getpwnam(user);
	if (!pwd) {
		_PAM_JAIL_ERROR("getpwnam error: %s", strerror(errno));
		return _PAM_JAIL_SYSERR;
	}
	ret = getgrouplist(pwd->pw_name, pwd->pw_gid, groups, &ngroups);
	if (ret == -1) {
		_PAM_JAIL_ERROR("getgrouplist error: too many groups");
		return _PAM_JAIL_SYSERR;
	}

	if (!(conf = fopen(CONFIG, "r"))) {
		_PAM_JAIL_ERROR("fopen error: %s", strerror(errno));
		return _PAM_JAIL_SYSERR;
	}

	for (;;) {
		readret = _pam_read_jaildescr(conf, &descr);
		switch (readret) {
		  case _PAM_READ_OK:
		  	_PAM_JAIL_DEBUG(opts, "Read group %s", descr.name);
		  	ret = _pam_checkgroup(descr.name, groups, ngroups);
			if (ret == -1)
				/* Do not bail out in this case, it most 
				 * probably means that group was not defined 
				 * on this system */
				break;
			if (ret == 1) 
				goto found;
			_free_descr(&descr);
			break;
		  case _PAM_READ_NOK:
		  	ret = _PAM_JAIL_INTERNALERR;
			goto out;
			break;
		  case _PAM_READ_NULL:
		  	break; /* continue */
		  case _PAM_READ_END:
		  	ret = _PAM_JAIL_GROUPNOTFOUND;
			goto out;
			break;
		  default:
		  	_PAM_JAIL_ERROR("Unexpected case: %i", ret);
		  	ret = _PAM_JAIL_INTERNALERR;
			goto out;
			break;
		}
	}
	/* Not reached */
				
found:
	opts->xid = descr.xid;
	ret = _PAM_JAIL_OK;

	/* Fall through */
out:
	fclose(conf);
	return ret;
}

static inline int
_pam_do_jail(struct _pam_opts *opts) 
{
	int ret;
	/* No xid is an error, since we're only called if a group was 
	 * matched in the first place */
	if (!opts->xid) {
		_PAM_JAIL_ERROR("Null xid in config file, aborting");
		return _PAM_JAIL_INTERNALERR;
	}
	if (opts->flags & _PAM_OPTS_NOJAIL) {
		_PAM_JAIL_DEBUG(opts, "Matched context %u, but not entering "
					"it for real", opts->xid);
		return _PAM_JAIL_OK;
	}
	if (opts->flags & _PAM_OPTS_PROXY) {
		_PAM_JAIL_DEBUG(opts, "Setting up terminal proxy");
		ret = clip_vlogin();
		if (ret) {
			_PAM_JAIL_ERROR("Failed to set up terminal proxy: %s",
						strerror(errno));
			return _PAM_JAIL_SYSERR;
		}
	}
	
	_PAM_JAIL_DEBUG(opts, "Entering context %u", opts->xid);
	ret = clip_enter_context(opts->xid);
	return (ret) ? _PAM_JAIL_SYSERR : _PAM_JAIL_OK;
}
	

/* This is the workhorse function.  All of the pam_sm_* functions should
 *  initialize a _pam_opts struct with the command line args and flags,
 *  then pass it to this function */
static int
_pam_jail(pam_handle_t *pamh, struct _pam_opts *opts)
{
	int ret;
	const char *user;

	ret = pam_get_user(pamh, &user, NULL);
	if (ret == PAM_CONV_AGAIN) {
		_pam_log(LOG_NOTICE, "%s: retry username lookup later", opts->module);
		return _PAM_JAIL_INCOMPLETE;
	} else if (ret != PAM_SUCCESS) {
		_PAM_JAIL_ERROR("%s: can't get username", opts->module);
		return _PAM_JAIL_SYSERR;
	}

	ret = _pam_get_jail(user, opts);

	switch (ret) {
		case _PAM_JAIL_GROUPNOTFOUND:
			if (opts->flags & _PAM_OPTS_NOTFOUNDFAILS) {
				_PAM_JAIL_ERROR("group not found, aborting");
				return _PAM_JAIL_INTERNALERR;
			}
			return _PAM_JAIL_OK;
			break;
		case _PAM_JAIL_OK:
			return _pam_do_jail(opts);
			break;
		default:
			_PAM_JAIL_ERROR("error while trying to get a jail");
			return ret;
	}
	/* Not reached */
}

#define pam_sm_func(pamh, flags, argc, argv, mod) do { \
	int ret;	\
	struct _pam_opts opts;	\
	\
	_pam_opts_init(&opts);	\
	opts.module = mod;	\
	_pam_opts_config(&opts, flags, argc, argv);	\
	\
	ret = _pam_jail(pamh, &opts);	\
	switch(ret) {	\
		case _PAM_JAIL_OK:	\
			_PAM_JAIL_DEBUG(&opts, "%s: success", opts.module);	\
			ret = PAM_SUCCESS;	\
			break;	\
	\
		case _PAM_JAIL_INCOMPLETE:	\
			_pam_log(LOG_NOTICE, "%s: returning incomplete", opts.module);	\
			ret = PAM_INCOMPLETE;	\
			break;	\
	\
		default:	\
			_PAM_JAIL_DEBUG(&opts, "%s: failure", opts.module);	\
			ret = PAM_AUTH_ERR;	\
			break;	\
	}	\
	_pam_opts_free(&opts);	\
	return ret;	\
} while (0)

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
	pam_sm_func(pamh, flags, argc, argv, "auth");
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
	_PAM_JAIL_ERROR("not a credentialator");
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
	pam_sm_func(pamh, flags, argc, argv, "account");
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	pam_sm_func(pamh, flags, argc, argv, "session");
}


PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags,
				    int argc, const char **argv)
{
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		int argc, const char **argv)
{
	_PAM_JAIL_ERROR("password management group is unsupported");
	return PAM_SERVICE_ERR;
}

#ifdef PAM_STATIC

/* static module data */

struct pam_module _pam_jail_modstruct = {
    "pam_jail",
    pam_sm_authenticate,
    pam_sm_setcred,
    pam_sm_acct_mgmt,
    pam_sm_open_session,
    pam_sm_close_session,
    pam_sm_chauthtok
};

#endif

