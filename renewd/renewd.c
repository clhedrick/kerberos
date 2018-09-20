/*
 * Copyright 2017 by Rutgers, the State University of New Jersey
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Rutgers not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original Rutgers software.
 * Rutgers makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/* 
   daemon to renew Kerberos credentials of active sessions
   The key is knowing which are active. For this, PAM and
   other ways to generate credentials are expected to register
   the credentials cache with the session keyring. This program
   then checks all session keyrings and renews all credential
   caches listed there.
*/
// for asprintf
#define _GNU_SOURCE   
#include <krb5.h>
#include <com_err.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <regex.h>
#include <pwd.h>

#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <search.h>
#include <keyutils.h>

/**************************

automatically renew tickets.

 **************************/

/*
 CODING NOTE:
 I'm treating uid and pid as if they might be long, because I want to be portable
   In fact on Intel they are 32 bit, whcih is int. Long is 64
 I can use printf with %lu because I will widen with a cast,
   but I can't use scanf %lu, because I can't narrow the assignment. So I use atol and assign it.
   The assignment narrows it to the actual size.
*/

#define KEYRING_PREFIX "KEYRING:persistent:"

int debug = 0;
int test = 0;
char * gssproxy_prefix = NULL;
char * gssproxy_prefix2 = NULL;

// hash used to collect uids of all credential caches registered with session keyrings

struct cc_entry {
  uid_t  uid;
  char * name;
  ENTRY *entry;
  int getcred;  // used getcred, so it should be renewed that way
  struct cc_entry *next;
};

struct cc_entry *cclist = NULL;

void mylog (int level, const char *format, ...)  __attribute__ ((format (printf, 2, 3)));
void mylog (int level, const char *format, ...) {
  va_list args;
  va_start (args, format);

  if (debug) {
    char *timestr;
    time_t now;
    now = time(0);
    timestr = ctime(&now);
    timestr[19] = '\0';
    vprintf(format, args);
    printf("\n");
  } else
    vsyslog(level, format, args);

  va_end(args);
}

// functions needed to check on status of
// tickets. They are defined in the Kerberos library
// but are not visible to user code. So we have to have
// our own copy.

static inline int
data_eq(krb5_data d1, krb5_data d2)
{
  return (d1.length == d2.length && (d1.length == 0 ||
				     !memcmp(d1.data, d2.data, d1.length)));
}

static inline int
data_eq_string (krb5_data d, const char *s)
{
  return (d.length == strlen(s) && (d.length == 0 ||
				    !memcmp(d.data, s, d.length)));
}

krb5_boolean is_local_tgt (krb5_principal princ, krb5_data *realm);

/* Return true if princ is the local krbtgt principal for local_realm. */
krb5_boolean
is_local_tgt(krb5_principal princ, krb5_data *realm)
{
  return princ->length == 2 && data_eq(princ->realm, *realm) &&
    data_eq_string(princ->data[0], KRB5_TGS_NAME) &&
    data_eq(princ->data[1], *realm);
}

/* 
   Return 1 if cache needs to be renewed. 0 if it doesn't. If cache is invalid or
   renew would fail, also return 0, since there's nothing we can do with it
*/
int
needs_renew(krb5_context kcontext, krb5_ccache cache, time_t minleft, int getcred) {
    krb5_error_code code, code2;
    krb5_cc_cursor cur = NULL;
    krb5_creds creds;
    krb5_principal princ = NULL;
    krb5_boolean found_tgt, found_current_tgt;
    int ret = 0;
    time_t now;

    now = time(0);

    if ((code = krb5_cc_get_principal(kcontext, cache, &princ))) {
      // get princial from the cache. It's a bit odd that a 
      // cache wouldn't have a principal. This could be either
      // a cache that wasn't fully set up or (more likely)a file
      // that isn't actually a cache.
      // return 0, but no need to print an error
      goto done;
    }

    // have to check all the credentials. We need to check whether
    // the TGT needs renewing.  This sets us up to iterate through the credentials
    if ((code = krb5_cc_start_seq_get(kcontext, cache, &cur))) {
      mylog(LOG_ERR, "can't start sequence for cache %s", error_message(code));
      if (cur) 
	krb5_cc_end_seq_get(kcontext, cache, &cur);
      goto done;
    }
    found_tgt = FALSE;   // found a TGT that isn't current
    found_current_tgt = FALSE;   // found a TGT that is current
    while (!(code = krb5_cc_next_cred(kcontext, cache, &cur, &creds))) {
      time_t allowedexpire;
      // only renewable creds are worth looking at. and must be TGT
      if ((creds.ticket_flags & TKT_FLG_RENEWABLE) && is_local_tgt(creds.server, &princ->realm)) {
	
	// enough time left, it's current
	if (((time_t)(uint32_t)creds.times.endtime - now) > minleft) {
	  found_current_tgt = TRUE;
	  krb5_free_cred_contents(kcontext, &creds);
	  break;
	}
	// not, is it renewable? Need to be able to get at least 10 min or it's silly
	//   and it must not be expired or it can't be renewed
	// if getcred, we'll use kgetcred, so ok if ticket is expired, but no
	//   point continuing to try tickets that have failed for a week
	if (getcred)
	  allowedexpire = (60 * 60 * 24 * 7);
	else
	  allowedexpire = 0;
	if ((((time_t)(uint32_t)creds.times.endtime + allowedexpire) >= now) && ((creds.times.renew_till - now) > (10*60))) {
	  // yup. but keep searching in case there's more than one
	  // and another one is still current
	  found_tgt = TRUE;
	} 
      }
      krb5_free_cred_contents(kcontext, &creds);
    }

    if (found_current_tgt) 
      mylog(LOG_DEBUG, "current ticket in %s", krb5_cc_get_name(kcontext, cache));
    else if (found_tgt)
      mylog(LOG_DEBUG, "renewable ticket in %s", krb5_cc_get_name(kcontext, cache));	

    if ((code2 = krb5_cc_end_seq_get(kcontext, cache, &cur))) {
      mylog(LOG_ERR, "close cc sequence failed %s", error_message(code2));
      goto done;
    }
    if (code && code != KRB5_CC_END) {
      mylog(LOG_ERR, "error in reading credentials from cache %s", error_message(code));
      goto done;
    }

    // return the right value

    // tgt current, no renew
    if (found_current_tgt)
      goto done;
    // found renewable tgt but not current, renew
    if (found_tgt)
      ret = 1;
    // otherwise not needed or can't be done
    
 done:
    if (princ != NULL)
      krb5_free_principal(kcontext, princ);

    return ret;
}

/*
 * renew the cache. Note that this closes ccache.
 * I'm a bit worried about race conditions. If the cache
 * is in /tmp, create a temp file and rename it to the real location.
 * If it's in the keyring, there's no way to do an atomic replacement.
 * So we have a brief race condition. This shouldn't matter, because
 * we do this a few minutes bfore the cache expires. NFS will have cached
 * the credentials in the kernel, and won't recheck until expiration. But
 * by that time we'll have it back the way it should be.
 */
static krb5_error_code
renew(krb5_context ctx, krb5_ccache ccache, time_t minleft, int getcred, uid_t uid, char *ccname) {
    krb5_error_code code;
    krb5_principal user = NULL;
    krb5_creds creds;
    int creds_valid = 0;
    const char *cctype = NULL;
    krb5_ccache newcache = NULL;
    char *oldname = NULL;
    char *newname = NULL;
    char *principal = NULL;
    char *tempname = NULL;

    memset(&creds, 0, sizeof(creds));

    cctype = krb5_cc_get_type(ctx, ccache);

    code = krb5_cc_get_principal(ctx, ccache, &user);
    if (code != 0) {
      // file is probably empty. Can't renew if there's no principal
      mylog(LOG_ERR, "error reading ticket cache %s", error_message(code));
      goto done;
    }

    // the actual renew operation

    if (getcred) {
      // ticket came from kgetcred. renew it by getting a new one
      // that makes sure we can do it even after a network failure
      // has caused the ticket to expire
      pid_t child;
      int status;

      code = krb5_unparse_name(ctx, user, &principal);
      if (code != 0) {
	mylog(LOG_ERR, "can't make sense of principal %s", error_message(code));
	goto done;
      }

      child = fork();

      if (child == 0) {
        int fd;
	struct passwd *pwd;
	char *env;

        // in child
        for ( fd=getdtablesize(); fd>=0; --fd) 
	  close(fd);

        fd = open("/dev/null",O_RDWR, 0);
	
        if (fd != -1) {          
	  dup2 (fd, STDIN_FILENO);
	  dup2 (fd, STDOUT_FILENO);
	  dup2 (fd, STDERR_FILENO);
	  if (fd > 2)
	    close (fd);
        }

	pwd = getpwuid(uid);
	if (!pwd) {
	  mylog(LOG_ERR, "can't find user %d", uid);
	  exit(1);
	}

	asprintf(&env, "KRB5CCNAME=%s", ccname);
	putenv(env);

        execl("/bin/kgetcred", "-U", pwd->pw_name, principal, NULL);
        mylog(LOG_ERR, "exec of kgetcred failed");
	exit(1);

      }

      // in parent

      waitpid(child, &status, 0);

      if (WEXITSTATUS(status)) {
	// kgetcred failed
        mylog(LOG_ERR, "kgetcred failed for %u %s", WEXITSTATUS(status), principal);
	code = status;
	goto done;
      }
      // finished
      mylog(LOG_INFO, "renewed %s for %d using kgetcred", ccname, uid);

      // success
      code = 0;
      goto done;
    }

    code = krb5_get_renewed_creds(ctx, &creds, user, ccache, NULL);
    creds_valid = 1;
    if (code != 0) {
      // expired ticket is going to be fairly normal for /tmp, so no error
      if (code != KRB5KRB_AP_ERR_TKT_EXPIRED)
	mylog(LOG_ERR, "renewing credentials %s", error_message(code));
      goto done;
    }
    
    mylog(LOG_INFO, "renewing cache %s", krb5_cc_get_name(ctx, ccache));

    // for files, put new creds in temp file and rename it
    if (strcmp(cctype, "FILE") == 0) {
      const char* oname;
      const char* nname;
      int i;

      oname = krb5_cc_get_name(ctx, ccache);
      i = asprintf(&tempname, "%s.%lu", oname, (long)getpid());
      if (i < 0) {
	mylog(LOG_ERR, "asprintf failed");
	goto done;
      }
      code = krb5_cc_resolve(ctx, tempname, &newcache);
      if (code) {
	mylog(LOG_ERR, "renewing credentials %s", error_message(code));
	goto done;
      }

      code = krb5_cc_initialize(ctx, newcache, user);
      if (code != 0) {
	mylog(LOG_ERR, "error reinitializing cache %s", error_message(code));
	goto done;
      }

      code = krb5_cc_store_cred(ctx, newcache, &creds);
      if (code != 0) {
	mylog(LOG_ERR, "error storing credentials %s", error_message(code));
	goto done;
      }

      // these are pointers into caches tht we are about to close, so copy them
      oldname = malloc(strlen(oname) + 1);
      strcpy(oldname, oname);

      nname = krb5_cc_get_name(ctx, newcache);
      newname = malloc(strlen(nname) + 1);
      strcpy(newname, nname);
      
      krb5_cc_close(ctx, ccache);      
      ccache = NULL;
      krb5_cc_close(ctx, newcache);      
      newcache = NULL;

      if (rename(newname, oldname)) {
	mylog(LOG_ERR, "unable to rename %s to %s", newname, oldname);
      }

      free(oldname);
      free(newname);

    } else {
      // anything other than the file we have to use the code that
      // kinit would use: reinitialized and store

      code = krb5_cc_initialize(ctx, ccache, user);
      if (code != 0) {
	mylog(LOG_ERR, "error reinitializing cache %s", error_message(code));
	goto done;
      }

      code = krb5_cc_store_cred(ctx, ccache, &creds);
      if (code != 0) {
	mylog(LOG_ERR, "error storing credentials %s", error_message(code));
	goto done;
      }
    }

done:
    /*
    if (ccache != NULL)
      krb5_cc_close(ctx, ccache);
    */
    if (tempname)
      free(tempname);
    if (principal)
      krb5_free_unparsed_name(ctx, principal);
    if (ccache)
      krb5_cc_close(ctx, ccache);
    if (newcache)
      krb5_cc_close(ctx, newcache);
    if (user != NULL)
      krb5_free_principal(ctx, user);
    if (creds_valid)
      krb5_free_cred_contents(ctx, &creds);

    

    return code;
}

// NULL or malloced string. caller must free it
char *read_whole_file(char *fname, long *argfsize) {
  int fd = open(fname, O_RDONLY);
  char *line;
  char *readptr;
  int fsize = 0;
  
  if (fd < 0) {
    *argfsize = 0;
    return NULL;
  }

  line = malloc(1000);
  readptr = line;
  while (1) {
    int ptrpos;
    int count = read(fd, readptr, 1000);
    if (count < 0) {
      close(fd);
      free(line);
      *argfsize = 0;
      return NULL;
    }
    if (count == 0)
      break;
    readptr += count;
    fsize += count;
    ptrpos = readptr - line;
    line = realloc(line, fsize + 1000);
    // block may have moved. need to adjust readptr to new block
    readptr = line + ptrpos;
  }

  close(fd);
  *argfsize = fsize;

  return line;
}

// create hash table and put entries for all credential caches current in use

void getccs() {
  struct dirent **namelist;
  int numdirs;
  int i;

  // max number of uids simulteaneously logged in 
  hcreate(10000);
  cclist = NULL;

  // there's no system call to read keys from other sessions,
  // so we have to read /proc/keys.

  numdirs = scandir("/proc", &namelist, NULL, alphasort);
  if (numdirs < 0) {
    mylog(LOG_ERR, "Couldn't scan /proc");
    return;
  }

  for (i = 0; i < numdirs; i++) {
    int first = namelist[i]->d_name[0];
    // only look at entries for procs
    if (first >= '0' && first <= '9') {
      char *fname;
      char *line;
      char *ptr;
      long fsize;
      size_t len = 0;
      uid_t uid;
      FILE *f;
      ENTRY entry;
      char *cp;
      char *uidend;
      char *path;

      // get uid
      asprintf(&fname, "/proc/%s/status", namelist[i]->d_name);
      f = fopen(fname, "r");
      if (!f) {
	free(fname);
	free(namelist[i]);
	continue;
      }
      free(fname);

      line = NULL;
      while (getline(&line, &len, f) >= 0) {
	if (strncmp(line, "Uid:", strlen("Uid:")) == 0)
	  break;
      }
      fclose(f);

      // must have a uid or we ignore process
      if (line == NULL || strncmp(line, "Uid:", strlen("Uid:")) != 0) {
	if (line)
	  free(line);
	free(namelist[i]);
	continue;
      }

      ptr = line + strlen("Uid:") + 1;

      // now have uid in ptr. put it in uid for later
      // there are actually 4 numbers, but we want the first, real uid
      uid = strtol(ptr, &uidend, 10);
      *uidend = '\0';

      // now have a UID. Add entry to hash
      // now have name in normalized and uid in uid
      entry.key = ptr;
      if (hsearch(entry, FIND) == NULL) {
	// didn't find it, add
	struct cc_entry *nentry = malloc(sizeof(struct cc_entry));
	nentry->next = cclist;
	nentry->name = malloc(strlen(ptr) + 1);
	strcpy(nentry->name, ptr);
	nentry->uid = uid;
	entry.key = nentry->name;
	entry.data = (void *)nentry;
	cclist = nentry;
	nentry->entry = hsearch(entry, ENTER);
      }

      if (line)
	free(line);

      // done with UID, now make an entry for ccname if we can find it
      asprintf(&fname, "/proc/%s/environ", namelist[i]->d_name);
      line = read_whole_file(fname, &fsize);
      if (!line) {
	free(fname);
	free(namelist[i]);
	continue;
      }
      free(fname);

      // structure is multiple null terminated strings
      // see if we have our env variable
      ptr = line;
      while (ptr < (line + fsize)) {
  	if (strncmp("KRB5CCNAME=", ptr, strlen("KRB5CCNAME=")) == 0)
	  break;
	ptr = ptr + strlen(ptr) +1;
      }

      // didn't find anything
      if (ptr >= (line + fsize)) {
	free(line);
	free(namelist[i]);
	continue;
      }

      // need value;
      ptr += strlen("KRB5CCNAME=");

      // now have env variable in ptr
      // if it's KEYRING:persistrnt:nnnn:xxx, drop xxx

      if (strncmp(ptr, KEYRING_PREFIX, strlen(KEYRING_PREFIX)) == 0) {
	char *cp2;
	cp = ptr + strlen(KEYRING_PREFIX);
	// look for KEYRING:persistent:nnn:xcc
	cp2 = strchr(cp, ':');
	// kill the last :
	if (cp2)
	  *cp2 = '\0';
      }
      // path will be normalized CC name
      // one more thing: we need to know who the owner is
      // if it isn't the process owner, ignore it, to avoid a user
      // getting us to hang onto another user's cc

      if (strncmp(ptr, "FILE:", strlen("FILE:")) == 0 ||
	  *ptr == '/') {
	// it's a file, use the owner
	struct stat statbuf;
	path = ptr;
	if (*path != '/')
	  path += strlen("FILE:");
	if (stat(path, &statbuf) == 0) {
	  // wrong user, ignore this
	  if (statbuf.st_uid != uid) {
	    free(line);
	    free(namelist[i]);
	    continue;
	  }
	}
      } else if (strncmp(ptr, KEYRING_PREFIX, strlen(KEYRING_PREFIX)) == 0) {
	uid_t kuid = atol(ptr + strlen(KEYRING_PREFIX));
	if (kuid != uid) {
	  free(line);
	  free(namelist[i]);
	  continue;
	}
	path = ptr;
      } else {
	// not keyring and doesn't start with /. Seems like junk
	free(line);
	free(namelist[i]);
	continue;
      }      
	
      // looks valid, save it

      entry.key = path;
      if (hsearch(entry, FIND) == NULL) {
	// didn't find it, add
	struct cc_entry *nentry = malloc(sizeof(struct cc_entry));
	nentry->next = cclist;
	nentry->name = malloc(strlen(path) + 1);
	strcpy(nentry->name, path);
	nentry->uid = uid;
	entry.key = nentry->name;
	entry.data = (void *)nentry;
	cclist = nentry;
	nentry->entry = hsearch(entry, ENTER);
      }
      free(namelist[i]);
      free(line);      
    } else
      free(namelist[i]);    
  }
  free(namelist);
}

// free malloced uids from hash
void freeccs() {
  while (cclist) {
    struct cc_entry *next = cclist->next;
    free(cclist->name);
    free(cclist);
    cclist = next;
  }
  hdestroy();
}

// go through all uids that are active and renew the primary cache for that uid if necessary
void maybe_renew(krb5_context ctx, char *ccname, time_t minleft, struct cc_entry *ccentry) {
    krb5_ccache cache = NULL;
    int code;
    int changeduid = 0;

    // we want to run as the owner of the cache. If it's a file
    // if_reg_cc changed ownership to user. 
    if ((strncmp(ccname, "FILE:", 5) == 0 ||
    	 strncmp(ccname, "/", 1) == 0)) {
      setresuid(ccentry->uid, ccentry->uid, -1L);
      changeduid = 1;
    }
    
    code = krb5_cc_resolve(ctx, ccname, &cache);
    if (code) {
      mylog(LOG_ERR, "can't resolve %s %s", ccname, error_message(code));      
      if (cache)
	krb5_cc_close(ctx, cache);
      cache = NULL;
      if (changeduid) {
	setresuid(0L, 0L, -1L);
      }
      return;
    }
			   
    if (needs_renew(ctx, cache, minleft, 0)) {
      renew(ctx, cache, minleft, 0, ccentry->uid, ccname);
      // renew closes
    } else {
      krb5_cc_close(ctx, cache);
    }
    cache = NULL;

    if (changeduid) {
      setresuid(0L, 0L, -1L);
    }
}


/* 
   Delete if file is not OK. It's OK if it is one of
   * in the list
   * unexpired
   * less than 5 min old [in case it's in the middle of being created]
   name is just the file name assume it's got /tmp in front of it
*/
int
maybe_delete(krb5_context kcontext, char *name, char *filename, int only_valid, struct cc_entry *ccentry) {
    krb5_error_code code;
    krb5_ccache cache = NULL;
    char *newname;
    
    // 1. is it in the hash, i.e. still in use?
    // we'll keep it around even if it is expired
    // that should only happen if renew failed
    if (ccentry) {
      return 0;
    }
      
    // not in use. kill it

    code = krb5_cc_resolve(kcontext, name, &cache);

    if (!code) {
      code = krb5_cc_destroy(kcontext, cache);
      if (code)
	mylog(LOG_ERR, "Delete old cache failed %s %s\n", name, error_message(code));
      else 
	mylog(LOG_INFO, "Deleted old cache %s", name);
    } else {
      mylog(LOG_DEBUG, "Old cache to be deleted not found: %s %s\n", name, error_message(code));
      if (cache)
	krb5_cc_close(kcontext, cache); // not likely we have a cache if resolv failed
    }

    // remove entry from /run/renewdccs

    asprintf(&newname, "/run/renewdccs/%s", filename);
    unlink(newname);
    free(newname);

    return 1;

}

void handle_all(krb5_context kcontext, int only_valid, time_t minleft, int do_del) {
  struct dirent **namelist;
  int numdirs;
  int i;

  numdirs = scandir("/run/renewdccs", &namelist, NULL, alphasort);
  if (numdirs < 0) {
    mylog(LOG_ERR, "Couldn't scan /run");
    return;
  }

  // this is safer than opendir because the semantics of
  // that aren't well defined if you delete files
  for (i = 0; i < numdirs; i++) {
    char *filename = namelist[i]->d_name;
    char *ccname;
    char *ccmem; // original malloc
    char *key;
    int deleted = 0;
    ENTRY entry;
    ENTRY *fentry;
    struct cc_entry *ccentry = NULL;
    char *cp, *cp2;

    if (strcmp(filename, ".") == 0 ||
	strcmp(filename, "..") == 0) {
      free(namelist[i]);
      continue;
    }

    // translate from filename to ccname
    ccmem = malloc(strlen(filename) + 1);
    ccname = ccmem;
    cp = filename;
    cp2 = ccname;
    while (*cp) {
      char ch = *cp;
      if (ch == '\\')
	*cp2 = '/';
      else
	*cp2 = ch;
      cp++;
      cp2++;
    }
    *cp2 = '\0';

    // normaize it, remove FILE: and remove trailing stuff from keyring
    cp = NULL;
    if (strncmp(ccname, "FILE:", 5) == 0) {
      ccname += 5;
    }
    // key to lookup in hash is normally the ccname
    key = ccname;
    if (*ccname == '/') {
      // if it's a GSSproxy ticket, we only ask that the user stil
      // has a process, so look up the uid, not the ccname
      if (strncmp(ccname, gssproxy_prefix,
		  strlen(gssproxy_prefix)) == 0)
        key += strlen(gssproxy_prefix);
      else if (strncmp(ccname, gssproxy_prefix2,
		  strlen(gssproxy_prefix2)) == 0)
        key += strlen(gssproxy_prefix2);
    } else if (strncmp(ccname, KEYRING_PREFIX, strlen(KEYRING_PREFIX)) == 0) {
      cp2 = ccname + strlen(KEYRING_PREFIX);
      cp = strchr(cp2, ':');
      if (cp)
	*cp = '\0';
    }      
    mylog(LOG_DEBUG, "checking cache %s", ccname);

    // ccname is now full ccache name, except that *cp may need to be
    // restored
    // look it up
    entry.key = key;
    if ((fentry = hsearch(entry, FIND))) {
      ccentry = (struct cc_entry *)fentry->data;
    }
    // restore ccname to full ccname
    if (cp)
      *cp = ':';
    // special problem: there's a brief time in sssd when the cache
    // has been created but the user process hasn't been started. If
    // we look during that time we don't want to delete. So if there's
    // no ccentry check whether the file was created very recently.
    // if so, skip the delete
    if (do_del) {
      int skipdel = 0;
      if (!ccentry) {
	char *statfile;
	struct stat statbuf;
	time_t now = time(0);

	asprintf(&statfile, "/run/renewdccs/%s", filename);
	if (stat(statfile, &statbuf) == 0) {
	  // 2 min should be enough even for X2go
	  if ((now - statbuf.st_mtime) < 120) {
	    skipdel = 1;
	  }
	}
	free(statfile);
      }
      if (!skipdel)
	deleted = maybe_delete(kcontext, ccname, filename, only_valid, ccentry);
    }
    // can't renew if it's not registered, becsuse we need the uid
    if (minleft && !deleted && ccentry)
      maybe_renew(kcontext, ccname, minleft, ccentry);

    free(ccmem);
    free(namelist[i]);
  }

  free(namelist);

}


void usage(char * progname) {
  printf("%s [-w waittime][-m minleft][-r renewwait][-d]\n    Waittime - time between main loops, minutes\n    Renewwait - time between attempts to renew a ticket, minutes\n    Minleft - renew if less than this left, minutes\n       Should be less than default ticket lifetime by at least 10 minutes\n    -d says to run in the foreground and print log messages to terminal\n", progname);
  exit(0);
}

int main(int argc, char *argv[])
{
  extern int opterr, optind;
  extern char * optarg;
  char *progname;
  char ch;
  unsigned long wait = 5; // active every N minutes
  unsigned long minleft = 12 * 60; // must have that much left or renew
  unsigned long renewwait = 60; // attempt renew every N minutes
  char *wait_str = NULL;
  char *min_str = NULL;
  char *rwait_str = NULL;
  char *default_str = NULL;
  char *delete_mode = NULL;
  time_t nextrenew = 0;
  krb5_context context;
  char *default_realm = NULL;
  int err = 0;
  krb5_data realm_data;

  progname = *argv;

  opterr = 0;
  while ((ch = getopt(argc, argv, "w:m:r:dt")) != -1) {
    switch (ch) {
    case 'w':
      wait_str = optarg;
      break;
    case 'm':
      min_str = optarg;
      break;
    case 'r':
      rwait_str = optarg;
      break;
    case 'd':
      debug++;
      break;
    case 't':
      debug++;
      debug++;
      test++;
      break;
    case '?':
    default:
      usage(progname);
      exit(1);
      break;
    }
  }

  if (geteuid()) {
    mylog(LOG_ERR, "must run as root");
  }

  // just to get a clean environment
  clearenv(); 

  if (!debug) {
    int i;
    int fd;
    if (fork()) {
      // parent exits
      exit(0);
    }
    /* open a log connection */
    openlog("renewd", 0, LOG_DAEMON);

    setsid(); // make process independent

    // close all descriptors
    for ( i=getdtablesize(); i>=0; --i)
      close(i);

    // attach them to something known
    fd = open("/dev/null",O_RDWR, 0);

    if (fd != -1) {
      dup2 (fd, STDIN_FILENO);
      dup2 (fd, STDOUT_FILENO);
      dup2 (fd, STDERR_FILENO);
      if (fd > 2)
	close (fd);
    }

  }

  chdir("/tmp"); // should be irrelevant. but just in case
  umask(077); // just to get something known; we don't create any files

  err = krb5_init_context(&context);
  if (err) {
    mylog(LOG_ERR, "can't init context %s", error_message(err));
    exit(1);
  }
  
  if ((err = krb5_get_default_realm(context, &default_realm))) {
    mylog(LOG_ERR, "unable to get default realm %s", error_message(err));
    exit(1);
  }

  realm_data.data = default_realm;
  realm_data.length = strlen(default_realm);

  krb5_appdefault_string(context, "renewd", &realm_data, "delete", "all", &delete_mode);
  krb5_appdefault_string(context, "renewd", &realm_data, "wait", "5", &default_str);
  // allow ours to be different than register-cc for a weird special case with Zeppelin
  krb5_appdefault_string(context, "renewd", &realm_data, "credcopy", NULL, &gssproxy_prefix2);
  krb5_appdefault_string(context, "register-cc", &realm_data, "credcopy", NULL, &gssproxy_prefix);
  // we want the prefix, i.e. the ccache name before the %
  if (gssproxy_prefix) {
    char *cp = strchr(gssproxy_prefix, '%');
    if (cp)
      *cp = '\0';
  }
  if (gssproxy_prefix2) {
    char *cp = strchr(gssproxy_prefix2, '%');
    if (cp)
      *cp = '\0';
  }

  if (wait_str) // overridden by arg
    wait = atol(wait_str);
  else
    wait = atol(default_str);
  krb5_appdefault_string(context, "renewd", &realm_data, "minleft", "720", &default_str);
  if (min_str) // overriden by arg
    minleft = atoi(min_str);
  else
    minleft = atoi(default_str);
  krb5_appdefault_string(context, "renewd", &realm_data, "renewwait", "60", &default_str);
  if (rwait_str) // overriden by arg
    renewwait = atoi(rwait_str);
  else
    renewwait = atoi(default_str);

  while (1) {
    struct cc_entry *entry;
    time_t renew_left;

    // pass 1. renew primary caches only

    time_t now = time(0);
    time_t nextloop = now + wait * 60;

    // checkanonymous(context, 60 * (wait + 10));

    if (!test)
      mylog(LOG_DEBUG, "main loop");

    getccs(); // put uids of all procs into the hash

    entry = cclist;
    while (entry) {
      entry = entry->next;
    }

    if (now >= nextrenew && !test) {
      mylog(LOG_DEBUG, "doing renewal");
      renew_left = 60 * minleft;
      nextrenew = now + 60 * renewwait;
    } else
      renew_left = 0;

    if (test)
      handle_all(context, strcmp(delete_mode, "valid") == 0,
		 0, 0);
    else
      handle_all(context, strcmp(delete_mode, "valid") == 0,
		 renew_left, (strcmp(delete_mode, "none") != 0));

    if (test)
      exit(0);

    freeccs();

    now = time(0);

    if (nextloop > now)
      sleep(nextloop - now);

  }


  if (err) {
    exit(1);
  }
  exit(0);
}


