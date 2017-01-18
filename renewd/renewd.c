
#include <krb5.h>
#include <com_err.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
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

/**************************

automatically renew tickets.
This is difficult because there's no way to atomically update a cache.
Current tools that do this are subject to race conditions, which in production actually do produce failures,
   particularly with Kerberized NFS.

This program only works for KEYRING caches, because it's easier to avoid race conditions with them.
The major loop will trigger once every 20 min or so.
There is a second phase delayed two minutes after the first phase

Phase 1:
Find all users logged in.
For each user
   Get their primary ccache.
   If it is about to expire, 
     create a new cache with renewed tickets
     give it a name that lets us know it's one we created.
     make it primary

Phase 2:
For each user
   Get all their caches
   For those we didn't create, if it is about to expire
     init it and put renewed credentials in it
   (This is the way kinit -R works.)

The reason we have to reinit an existing cache in phase 2 is that ssh
sessions have an environment variable pointing to a specific cache.
rpc.gssd will use the primary cache.

For rpc.gssd, we have to renew the primary cache. The only safe way to do that is to create
   a new one with the renewed credentials. The old one will be deleted by the kernel when it expires.

Ssh sets an environment variable to a specific cache. So we have to renew all caches, in case
   someone is using it in ssh. It has to stay in the same location. So we have to use the standard
   protocol of reiniting it and putting renewed keys in. This has to be done after a new primary
   cache is defined, and we need a brief pause in case one of the ssh caches was initially the primary
   and gssproxy is in the middle of processing it.

The second phase has to ignore caches we created. If we renew them we'll get a never ending increasing
   pool of those caches.

A similar approach could be used for /tmp if necesary. However the system won't delete expired caches,
so we'd have to do it (or run a separate cron job). The difference is that there's no primary cache
for /tmp. However rpc.gssd will look at all caches. So we could use a differnt naming format for our
own cache, and then use a similar algorithm. But no point writing a separate set of code when our
systems will be set to use KEYRING all the time.


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

// hash used to collect uids of all running processes
ENTRY *uidlist;

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
needs_renew(krb5_context kcontext, krb5_ccache cache, time_t minleft) {
    krb5_error_code code, code2;
    krb5_cc_cursor cur;
    krb5_creds creds;
    krb5_principal princ;
    krb5_boolean found_tgt, found_current_tgt, found_current_cred;
    int ret = 0;
    time_t now;

    now = time(0);

    if ((code = krb5_cc_get_principal(kcontext, cache, &princ))) {
      // this is normal. user doesn't have a cache
      // return 0, but no need to print an error
      goto done;
    }
    if ((code = krb5_cc_start_seq_get(kcontext, cache, &cur))) {
      mylog(LOG_ERR, "can't start sequence for cache %s", error_message(code));
      goto done;
    }
    found_tgt = found_current_tgt = found_current_cred = FALSE;
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
	if ((creds.times.renew_till - now) > (10*60)) {
	  // yup. but keep searching in case there's more than one
	  // and another one is still current
	  found_tgt = TRUE;
	}
      }
      krb5_free_cred_contents(kcontext, &creds);
    }

    if ((code2 = krb5_cc_end_seq_get(kcontext, cache, &cur))) {
      mylog(LOG_ERR, "close cc sequence failed %s", error_message(code2));
      goto done;
    }
    if (code && code != KRB5_CC_END) {
      mylog(LOG_ERR, "error in reading credentials from cache %s", error_message(code));
      goto done;
    }

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
 * Renew the usual way: reiniting.
 * only renew if within minleft sec of expiration
 */
static krb5_error_code
renew(krb5_context ctx, krb5_ccache ccache, time_t minleft) {
    krb5_error_code code;
    krb5_principal user = NULL;
    krb5_creds creds;
    int creds_valid = 0;

    memset(&creds, 0, sizeof(creds));

    /*
    code = krb5_cc_resolve(ctx, cachename, &ccache);
    if (code != 0) {
      mylog(LOG_ERR, "error opening ticket cache %s", error_message(code));
      goto done;
    }
    */

    if (!needs_renew(ctx, ccache, minleft))
      goto done;

    mylog(LOG_DEBUG, "renewing cache %s", krb5_cc_get_name(ctx, ccache));

    code = krb5_cc_get_principal(ctx, ccache, &user);
    if (code != 0) {
      // file is probably empty. Can't renew if there's no principal
      mylog(LOG_ERR, "error reading ticket cache");
      goto done;
    }

    code = krb5_get_renewed_creds(ctx, &creds, user, ccache, NULL);
    creds_valid = 1;
    if (code != 0) {
      mylog(LOG_ERR, "renewing credentials %s", error_message(code));
      goto done;
    }
    
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

done:
    /*
    if (ccache != NULL)
      krb5_cc_close(ctx, ccache);
    */
    if (user != NULL)
      krb5_free_principal(ctx, user);
    if (creds_valid)
      krb5_free_cred_contents(ctx, &creds);
    return code;
}

/* 
 * check all caches except the ones we generated for current user
 * caller is expected to change euid.
 */ 

static void
renewalluser(krb5_context kcontext, uid_t uid, time_t minleft) {
  krb5_error_code code;
  krb5_ccache cache = NULL;
  krb5_cccol_cursor cursor;
  char namebuf[1024];

  snprintf(namebuf, sizeof(namebuf)-1, "KEYRING:persistent:%lu", (unsigned long)uid);

  // cccol_cursor_new uses the default collection from the content
  // The context will normally have a collection for the current user
  // but this context was set up by root. So we need to set the
  // collection explicitly for the user we're checking.
  krb5_cc_set_default_name(kcontext, namebuf);

  code = krb5_cccol_cursor_new(kcontext, &cursor);
  if (code != 0) {
    mylog(LOG_ERR, "error starting cache list %s", error_message(code));
    goto done;
  }

  while (!(code = krb5_cccol_cursor_next(kcontext, cursor, &cache)) &&
	 cache != NULL) {
    const char * cname = krb5_cc_get_name(kcontext, cache);
    // ignore our own
    if (strstr(cname, ":renewd-") == NULL)
      renew(kcontext, cache, minleft);
    krb5_cc_close(kcontext, cache);
    cache = NULL;
  }
 done:
  if (cache)
    krb5_cc_close(kcontext, cache);
  krb5_cccol_cursor_free(kcontext, &cursor);

}

/*
 * Renew the primary entry. Create a new cache and put the
 * renewed thing there.
 */
static krb5_error_code
renewp(krb5_context ctx, uid_t uid, time_t minleft) {
    krb5_error_code code;
    krb5_ccache ccache = NULL;
    krb5_ccache ncache = NULL;
    krb5_principal user = NULL;
    krb5_principal nuser = NULL;
    krb5_creds creds;
    int creds_valid = 0;
    char namebuf[1024];
    time_t now;
    int pass = 100;

    memset(&creds, 0, sizeof(creds));

    // This should be the default cache collection. Do it explicitly
    // because this is a different uid than our own
    // cc_resolve will get the primary cache from the collection
    snprintf(namebuf, sizeof(namebuf)-1, "KEYRING:persistent:%lu", (unsigned long)uid);

    ccache = NULL;
    code = krb5_cc_resolve(ctx, namebuf, &ccache);
    if (code) {
      mylog(LOG_ERR, "error resolving %s %s", namebuf, error_message(code));
      goto done;
    }

    if (!needs_renew(ctx, ccache, minleft))
      goto done;

    mylog(LOG_DEBUG, "renewing principal cache %s", krb5_cc_get_name(ctx, ccache));

    code = krb5_cc_get_principal(ctx, ccache, &user);
    if (code != 0) {
      // file is probably empty. Can't renew if there's no principal
      mylog(LOG_ERR, "error reading ticket cache");
      goto done;
    }

    code = krb5_get_renewed_creds(ctx, &creds, user, ccache, NULL);
    creds_valid = 1;
    if (code != 0) {
      mylog(LOG_ERR, "renewing credentials %s", error_message(code));
      goto done;
    }
    
    now = time(0);

    while (pass > 0) {

      // you'd expect us just to do new_unique to make a new cache. However
      // we need to specify the name so we can detect that we created it later.
      // new_unique ignores the prototype passed. So we have to simulate new_unique
      // ourselves. Try 100 times to create new cache. Just increment the time
      // to get the next try. This isn't wonderful code, but it shouldn't ever
      // actually be needed.
      snprintf(namebuf, sizeof(namebuf)-1, "KEYRING:persistent:%lu:renewd-%lu", (unsigned long)uid, now);
    
      code = krb5_cc_resolve(ctx, namebuf, &ncache);
      if (code) {
	mylog(LOG_ERR, "error resolving %s %s", namebuf, error_message(code));
	goto done;
      }

      // cc_resolve will work whether the cache exists or not. get_principal tells
      // us whether it actually does exist. This could actually produce the wrong
      // result if there's a cache in the middle of being created. But the only one
      // that should create caches of this form is us. That means there's a limit to how
      // far it makes sense to take this.
      code = krb5_cc_get_principal(ctx, ncache, &nuser);
      if (nuser) {
	krb5_free_principal(ctx, nuser);
      }
      if (code) {
	// if we can't get a princpal for the cache it's probably not set up.
	// i.e. it's a new one. We're done.
	break; 
      }
      // valid cache. We need a new one so close it and try again
      krb5_cc_close(ctx, ncache);
      ncache = NULL;
      pass--;
      now++;
    }

    if (pass == 0) {
      // run out of 100 tries. We give up
      mylog(LOG_ERR, "unable to allocate new cache; all 100 possibilities failed");
      goto done;
    }

    // here if we have a new cache. Set it up
    code = krb5_cc_initialize(ctx, ncache, user);
    if (code != 0) {
      mylog(LOG_ERR, "error reinitializing cache %s", error_message(code));
      goto done;
    }
    code = krb5_cc_store_cred(ctx, ncache, &creds);
    if (code != 0) {
      mylog(LOG_ERR, "error storing credentials %s", error_message(code));
      goto done;
    }

    // make the new cache primary
    code = krb5_cc_switch(ctx, ncache);
    if (code != 0) {
      mylog(LOG_ERR, "unable to make new cache the primary %s", error_message(code));
      goto done;
    }

    krb5_cc_close(ctx, ncache);    
    ncache = NULL;
    
done:
    // if ncache is there we took an error exit.
    // try to avoid leaving a bad cache around
    if (ncache != NULL) {
      krb5_cc_destroy(ctx, ncache);
    }
    if (ccache != NULL)
      krb5_cc_close(ctx, ccache);
    if (user != NULL)
      krb5_free_principal(ctx, user);
    if (creds_valid)
      krb5_free_cred_contents(ctx, &creds);
    return code;
}

/* find controlling uid for a process. Linux procfs. Obviously only works with Linux */
uid_t getprocuid(pid_t pid) {
  char buffer[1024];
  char *line;
  size_t size;
  uid_t ret;
  FILE *statfile;

  snprintf(buffer, sizeof(buffer)-1, "/proc/%lu/status", (unsigned long)pid);
  statfile = fopen(buffer, "r");
  if (!statfile) {
    mylog(LOG_ERR, "can't open %s %m", buffer);
    return -1;
  }
  size = 512;
  line = malloc(size);
  if (!line) {
    fclose(statfile);
    mylog(LOG_ERR, "malloc failed %m");
    return -1;
  }
  while (getline(&line, &size, statfile) >= 0) {
    if (strncmp(line, "Uid:", 4) == 0) {
      ret = atol(line+4);
      free(line);
      fclose(statfile);      
      return ret;
    }
  }
  mylog(LOG_ERR, "Uid: not in /proc/N/stat");
  free(line);
  fclose(statfile);      
  return -1;  
    
}

// create hash table and put the users of all current running processes in it
// Note that there's no function to enumerate all hash entries, so we have
// to put the entries into a list. Fortunately we don't need to start any data
// with the uid. We just need to remember the uid's. We use the data portion
// of the hash entry to point to the previous item in the list.
void getuids() {
  DIR *procdir;
  struct dirent *dir;
  char *residual;
  pid_t pid;

  // max number of uids simulteaneously logged in 
  hcreate(10000);
  uidlist = NULL;

  procdir = opendir("/proc");
  if (!procdir) {
    mylog(LOG_ERR, "unable to open /proc %m");
    exit(1);
  }
  // /proc has an entry for each proces, but also other things. So
  // make sure we only look at entrie that are purely numbers.
  while ((dir = readdir(procdir))) {
    residual = NULL; // anything left after a number?
    pid = strtol(dir->d_name, &residual, 10);
    if (residual && *residual == '\0') { // nothing left over after number
      uid_t uid = getprocuid(pid);
      if (uid != -1L) {
	char uidbuf[32];
	ENTRY uident;

	snprintf(uidbuf, sizeof(uidbuf), "%lu", (unsigned long)uid);
	// fixed buffer. 
	// avoid mallocing unless we need a new entry
	uident.key = uidbuf;
	// if uid isn't in the hash, put it there
	if (hsearch(uident, FIND) == NULL) {
	  // need a new entry, now malloc space for the uid
	  uident.key = malloc(strlen(uidbuf) + 1);
	  strcpy(uident.key, uidbuf);
	  // point to previous entry in the list
	  uident.data = uidlist;
	  // this is now the new tail of the list
	  uidlist = hsearch(uident, ENTER);
	}
      }
    }
  }
  closedir(procdir);
}

// free malloced uids from hash
void freeuids() {
  while (uidlist) {
    ENTRY *next = (ENTRY *)uidlist->data;
    free(uidlist->key);
    uidlist = next;
  }
  hdestroy();
}

// go through all uids that are active and renew the primary cache for that uid if necessary
void renewpall(krb5_context ctx, time_t minleft) {
  ENTRY *uident = uidlist;
  while (uident) {
    uid_t uid;
    uid = atol(uident->key);
    seteuid(uid);
    renewp(ctx, uid, minleft);
    seteuid(0L);
    uident = (ENTRY *)uident->data;
  }
}

// go through all uids that are active and renew caches other than the ones we created if necessary
// There's one special case to worry about. Suppose the user just did kinit. That created a cache. If it's the
// first one it will be primary. Suppose renewp found it didn't need renewing. But this is called 2 min later.
// In theory it could now need renewing. That's a problem because we don't want to do traditional renews on the
// primary cache. At least not until we've copied it. FOr that reason, minleft should be enough less than
// the value used for renewpall that if a primary cache wasn't renewed in pass 1 it won't be in pass 2 either.
void renewall(krb5_context ctx, time_t minleft) {
  ENTRY *uident = uidlist;
  while (uident) {
    uid_t uid;
    uid = atol(uident->key);
    seteuid(uid);
    renewalluser(ctx, uid, minleft);
    seteuid(0L);
    uident = (ENTRY *)uident->data;
  }
}

void usage(char * progname) {
  printf("%s [-w waittime][-d]\n    Waittime - time between main loops, minutes; default 60\n       Should be less than default ticket lifetime by at least 10 minutes\n    -d says to run in the foreground and print log messages to terminal\n", progname);
  exit(0);
}

int main(int argc, char *argv[])
{
  extern int opterr, optind;
  extern char * optarg;
  char *progname;
  char ch;
  unsigned long wait = 60; // 1 hour

  krb5_context context;
  int err = 0;

  progname = *argv;

  opterr = 0;
  while ((ch = getopt(argc, argv, "w:d")) != -1) {
    switch (ch) {
    case 'w':
      wait = atoi(optarg);
      break;
    case 'd':
      debug++;
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
  umask(027); // just to get something known, we shouldn't actually create any files

  err = krb5_init_context(&context);
  if (err) {
    mylog(LOG_ERR, "can't init context %s", error_message(err));
    exit(1);
  }
  
  while (1) {

    // pass 1. renew primary caches only

    time_t now = time(0);
    time_t nextloop = now + wait * 60;

    mylog(LOG_DEBUG, "main loop");

    getuids(); // put uids of all procs into the hash

    renewpall(context, 60 * (wait + 10));

    // wait 2 min for pass 2

    sleep(120);

    // pass 2. renew all caches we didn't create

    mylog(LOG_DEBUG, "renew normal caches");

    // See comments on renewall for why we use 6 rather than
    // 10 here.
    renewall(context, 60 * (wait + 6));
    freeuids();

    now = time(0);

    if (nextloop > now)
      sleep(nextloop - now);

  }


  if (err) {
    exit(1);
  }
  exit(0);
}

