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

int debug = 0;
int test = 0;

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
    printf("%8s ", timestr+11);
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
      // only renewable creds are worth looking at. and must be TGT
      if ((creds.ticket_flags & TKT_FLG_RENEWABLE) && is_local_tgt(creds.server, &princ->realm)) {
	// enough time left, it's current
	if ((creds.times.endtime - now) > minleft) {
	  found_current_tgt = TRUE;
	  krb5_free_cred_contents(kcontext, &creds);
	  break;
	}
	// not, is it renewable? Need to be able to get at least 10 min or it's silly
	// and it must not be expired or it can't be renewed
	// if getcred, we'll use kgetcred, so ok if ticket is expired
	if (getcred || ((creds.times.endtime >= now) && ((creds.times.renew_till - now) > (10*60)))) {
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

	setreuid(uid, uid);

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
    
    mylog(LOG_DEBUG, "renewing cache %s", krb5_cc_get_name(ctx, ccache));

    // for files, put new creds in temp file and rename it
    if (strcmp(cctype, "FILE") == 0) {
      const char* oname;
      const char* nname;
      char *tempname;
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

// create hash table and put entries for all credential caches current in use

void getccs() {
  char buffer[1024];
  FILE *keyfile;

  // max number of uids simulteaneously logged in 
  hcreate(10000);
  cclist = NULL;

  // there's no system call to read keys from other sessions,
  // so we have to read /proc/keys.

  keyfile = fopen("/proc/keys", "r");
  if (!keyfile) {
    mylog(LOG_ERR, "unable to open /proc/keys %m");
    exit(1);
  }
  // entries look like 
  //0074836e I--Q---     1 perm 3f010000     0     0 user      krbrenewd:ccname: 43
  // note that our test will also match krbrenewd:ccname:2, etc., so you
  // can register more than one file
  while (fgets(buffer, sizeof(buffer)-1, keyfile)) {
    char *id, *dummy, *description;
    int i;
    long len;
    key_serial_t serial;
    char *normalized;
    uid_t uid;
    ENTRY entry;

    // remove trailing new line
    i = strlen(buffer);
    if (buffer[i-1] == '\n')
      buffer[i-1] = '\0';

    id = strtok(buffer, " ");

    if (!id)
      continue;
    for (i = 2; i < 9; i++) {
      dummy = strtok(NULL, " ");
      if (!dummy)
	continue;
    }
    description = strtok(NULL, " ");
    if (!description)
      continue;

    if (strncmp(description, "krbrenewd:ccname:", strlen("krbrenewd:ccname:")) != 0 &&
	strncmp(description, "kgetcred:ccname:", strlen("kgetcred:ccname:")) != 0)
      continue;

    // found one, get the cc name
    serial = strtoul(id, NULL, 16);
    len = keyctl_read(serial, buffer, sizeof(buffer) - 1);
    if (len < 0) {
      mylog(LOG_ERR, "unable to read key value %m");
      continue;
    }
    buffer[len] = '\0';

    mylog(LOG_DEBUG, "cache registered with session: %s", buffer);

    // buffer should now be a cache name. normalize it
    if (strncmp(buffer, "FILE:", 5) == 0)
      normalized = buffer + 5;
    else 
      normalized = buffer;

    if (normalized[0] == '/') {
      struct stat statbuf;
      // file. use owner as uid
      if (stat(normalized, &statbuf)) {
	mylog(LOG_ERR, "can't stat %s %m", normalized);
	continue;
      }
      uid = statbuf.st_uid;
    } else if (strncmp(buffer, "KEYRING:persistent:", strlen("KEYRING:persistent:")) == 0) {
      // if anything persistent is defined, assume it's the primary
      char *uidstr = buffer + strlen("KEYRING:persistent:");
      char *uidend = strchr(uidstr, ':');
      if (uidend)
	*uidend = '\0';
      normalized = buffer;
      uid = atoi(uidstr);
    } else {
      mylog(LOG_ERR, "unsupported CC name %s", normalized);
      continue;
    }

    // now have name in normalized and uid in uid
    entry.key = normalized;
    if (hsearch(entry, FIND) == NULL) {
      // didn't find it, add
      struct cc_entry *nentry = malloc(sizeof(struct cc_entry));
      nentry->next = cclist;
      nentry->name = malloc(strlen(normalized) + 1);
      strcpy(nentry->name, normalized);
      nentry->uid = uid;

      entry.key = nentry->name;
      // set 1 if it credential gottne with kgetcred
      nentry->getcred = (strncmp(description, "kgetcred:ccname:", strlen("kgetcred:ccname:")) == 0);

      entry.data = (void *)nentry;

      cclist = nentry;
      nentry->entry = hsearch(entry, ENTER);

    }

  }
  fclose(keyfile);
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
void renewall(krb5_context ctx, time_t minleft) {
  struct cc_entry *entry = cclist;

  while (entry) {
    krb5_ccache cache;
    int code;

    // we want to run as the owner of the cache.
    seteuid(entry->uid);
    
    code = krb5_cc_resolve(ctx, entry->name, &cache);
    if (code) {
      mylog(LOG_ERR, "can't resolve %s %s", entry->name, error_message(code));      
      if (cache)
	krb5_cc_close(ctx, cache);
      cache = NULL;
      seteuid(0L);
      continue;
    }
			   
    if (needs_renew(ctx, cache, minleft, entry->getcred) && !test) {
      renew(ctx, cache, minleft, entry->getcred, entry->uid, entry->name);
      // renew closes
    } else {
      krb5_cc_close(ctx, cache);
    }
    cache = NULL;

    seteuid(0L);
    entry = entry->next;
  }

}

/* 
   Delete if file is not OK. It's OK if it is one of
   * in the list
   * unexpired
   * less than 5 min old [in case it's in the middle of being created]
   name is just the file name assume it's got /tmp in front of it
*/
void
maybe_delete(krb5_context kcontext, char *name, char *dir, int only_valid) {
    krb5_error_code code;
    krb5_cc_cursor cur = NULL;
    krb5_creds creds;
    krb5_principal princ = NULL;
    krb5_ccache cache = NULL;
    krb5_boolean ok = FALSE;
    time_t now;
    char filename[1024];
    ENTRY entry;
    struct stat statbuf;
    
    snprintf(filename, sizeof(filename)-1, "%s/%s", dir,  name);

    // 1. is it in the hash?

    // now have name in normalized and uid in uid
    entry.key = filename;
    if (hsearch(entry, FIND)) {
      if (debug > 1)
	mylog(LOG_DEBUG, "In hash: %s", filename);	
      return; // yes, it's still in use, return without doing anything
    }
      
    // 2. is it an unexpired cache?

    code = krb5_cc_resolve(kcontext, filename, &cache);

    if (!code)
      code = krb5_cc_get_principal(kcontext, cache, &princ);

    if (code && only_valid) {
      // not a valid cache, user has asked us to delete only valid ones
      if (debug > 1)
	mylog(LOG_DEBUG, "Not valid: %s", filename);	
      if (princ)
	krb5_free_principal(kcontext, princ);
      if (cache)
	krb5_cc_close(kcontext, cache);
      return;
    }
      
    if (!code)
      code = krb5_cc_start_seq_get(kcontext, cache, &cur);

    now = time(0);

    if (!code) {
      while (!(code = krb5_cc_next_cred(kcontext, cache, &cur, &creds))) {
	// only renewable creds are worth looking at. and must be TGT
	if ((creds.ticket_flags & TKT_FLG_RENEWABLE) && is_local_tgt(creds.server, &princ->realm)) {
	  // enough time left, it's current
	  if ((creds.times.endtime - now) >= 0) {
	    ok = TRUE;
	    krb5_free_cred_contents(kcontext, &creds);
	    break;
	  }
	}
	krb5_free_cred_contents(kcontext, &creds);
      }
    }

    if (princ)
      krb5_free_principal(kcontext, princ);
    if (cur)
      krb5_cc_end_seq_get(kcontext, cache, &cur);
    if (cache) {
      krb5_cc_close(kcontext, cache);
    }

    if (ok) {
      if (debug > 1)
	mylog(LOG_DEBUG, "Ticket OK: %s", filename);	
      return;  // yes, unexpired cache, nothing to do
    }

    // 3. created within the last 5 minutes

    if (stat(filename, &statbuf)) 
      return; // can't find it, nothing useful to do

    if (!S_ISREG(statbuf.st_mode)) {
      // not a file, don't try to unlink other stuff
      if (debug > 1)
	mylog(LOG_DEBUG, "Not a regular file: %s", filename);	
      return; 
    }

    if ((now - statbuf.st_mtime) < (5 * 60)) {
      if (debug > 1)
	mylog(LOG_DEBUG, "File recent: %s", filename);	
      return; // recent, nothign to do
    }

    unlink(filename);

    mylog(LOG_DEBUG, "Deleting old cache: %s", filename);

}

regex_t regex;
regex_t regex2;
char *dir2 = NULL;

int myfilter (const struct dirent *d) {
  return regexec(&regex, d->d_name, 0, NULL, 0) == 0;
}
  
int myfilter2 (const struct dirent *d) {
  return regexec(&regex2, d->d_name, 0, NULL, 0) == 0;
}
  


void delete_old(krb5_context kcontext, int only_valid) {
  struct dirent **namelist;
  int numdirs;
  int i;

  numdirs = scandir("/tmp", &namelist, myfilter, alphasort);
  if (numdirs < 0) {
    mylog(LOG_ERR, "Couldn't scan /tmp");
    return;
  }

  // this is safer than opendir because the semantics of
  // that aren't well defined if you delete files
  for (i = 0; i < numdirs; i++) {
    if (debug > 2)
      mylog(LOG_DEBUG, "checking %s", namelist[i]->d_name);
    maybe_delete(kcontext, namelist[i]->d_name, "/tmp", only_valid);
    free(namelist[i]);
  }

  free(namelist);

  // do we have to check something like /var/lib/gssproxy/client?
  if (dir2) {
    numdirs = scandir(dir2, &namelist, myfilter2, alphasort);
    if (numdirs < 0) {
      mylog(LOG_ERR, "Couldn't scan %s", dir2);
      return;
    }

    // this is safer than opendir because the semantics of
    // that aren't well defined if you delete files
    for (i = 0; i < numdirs; i++) {
      if (debug > 2)
	mylog(LOG_DEBUG, "checking %s", namelist[i]->d_name);
      maybe_delete(kcontext, namelist[i]->d_name, dir2, only_valid);
      free(namelist[i]);
    }
    
    free(namelist);

  }

}


void usage(char * progname) {
  printf("%s [-w waittime][-m minleft][-d]\n    Waittime - time between main loops, minutes\n    Minleft - renew if less than this left, minutes\n       Should be less than default ticket lifetime by at least 10 minutes\n    -d says to run in the foreground and print log messages to terminal\n", progname);
  exit(0);
}

int main(int argc, char *argv[])
{
  extern int opterr, optind;
  extern char * optarg;
  char *progname;
  char ch;
  unsigned long wait = 13; // active every N minutes
  unsigned long minleft = 41; // must have that much left or renew
  char *wait_str = NULL;
  char *min_str = NULL;
  char *default_str;
  krb5_context context;
  char *default_realm = NULL;
  int err = 0;
  krb5_data realm_data;
  char *pattern;
  char *delete_mode;
  char *pattern2;

  progname = *argv;

  opterr = 0;
  while ((ch = getopt(argc, argv, "w:m:dt")) != -1) {
    switch (ch) {
    case 'w':
      wait_str = optarg;
      break;
    case 'm':
      min_str = optarg;
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

  krb5_appdefault_string(context, "renewd", &realm_data, "pattern", "^krb5cc_", &pattern);
  krb5_appdefault_string(context, "renewd", &realm_data, "delete", "all", &delete_mode);
  krb5_appdefault_string(context, "register-cc", &realm_data, "credcopy", "", &pattern2);
  krb5_appdefault_string(context, "renewd", &realm_data, "wait", "13", &default_str);
  if (wait_str) // overridden by arg
    wait = atol(wait_str);
  else
    wait = atol(default_str);
  krb5_appdefault_string(context, "renewd", &realm_data, "minleft", "30", &default_str);
  if (min_str) // overriden by arg
    minleft = atoi(min_str);
  else
    minleft = atoi(default_str);

  // if we just want to look at ones we create:
  // if(regcomp(&regex, "^krb5cc_.*_cron$", 0)) {
  if(regcomp(&regex, pattern, 0)) {
    mylog(LOG_ERR, "Couldn't compile regex");
    exit(1);
  }

  // second place to scan?
  if (strlen(pattern2) > 0) {
    char *pat;
    char *cp = rindex(pattern2, '/');
    char *cp2;

    if (!cp) {
      mylog(LOG_ERR, "krb5.conf/register-cc/credcopy doesn't have a slash");
      exit(1);
    }
    // copy directory portion to dir2
    dir2 = malloc((cp - pattern2) + 1);
    strncpy(dir2, pattern2, (cp - pattern2));
    dir2[cp - pattern2] = '\0';

    // make a patern for stuff after /
    cp++; // get beyond slash
    pat = (char *)malloc(2 * strlen(cp) + 1);

    cp2 = pat;
    while (*cp) {
      if (*cp == '%' && (*(cp+1) == 'U' || *(cp+1) == 'u')) {
	*cp2++ = '.';
	*cp2++ = '*';
	cp += 2;
      } else if (index("^.*[$\\", *cp) != NULL) {
	*cp2++ = '\\';
	*cp2++ = *cp++;
      } else {
	*cp2++ = *cp++;
      }
    }
    *cp2 = '\0';

    // needs to be extended, since \ has opposite meaning for some chars in basic
    if(regcomp(&regex2, pat, 0)) {
      mylog(LOG_ERR, "Couldn't compile regex2");
      exit(1);
    }
  }

  while (1) {

    // pass 1. renew primary caches only

    time_t now = time(0);
    time_t nextloop = now + wait * 60;

    // checkanonymous(context, 60 * (wait + 10));

    mylog(LOG_DEBUG, "main loop");

    getccs(); // put uids of all procs into the hash

    renewall(context, 60 * minleft);

    if (test)
      exit(1);

    if (strcmp(delete_mode, "none") != 0)
      delete_old(context, strcmp(delete_mode, "valid") == 0);

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

