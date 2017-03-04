
#include <krb5.h>
#include <com_err.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <regex.h>

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

For each user with current processes renews (where needed)
 - primary cache in KEYRING
 - all caches in /tmp/krb5cc_NNN and /tmp/krb5cc_NNN_*

Because renewal isn't atomic, before the first renewal, creates a copy of
renewed credentials in /tmp/krb5cc_NNN-renew. That is deleted after 2 minutes.

rpc.gssd, which is used by NFS, looks first at the primary cache in KEYRING,
then all caches in /tmp owned by the user. Hence if it happens to hit one
during the process of renewal, it will eventually find /tmp/krb5cc_NNN-renew,
and use that.


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

struct uid_info {
  char * primary_cc;
  char * key;
  ENTRY *entry;
  struct uid_info *next_item;
};

struct uid_info *uidlist = NULL;

#define HOSTKT "/etc/krb5.keytab"
#define ANONCC "/tmp/krb5_cc_host"
#define ANONCCTEMP "/tmp/krb5_cc_host.new"
#define ANONCCTEMPNAME "FILE:/tmp/krb5_cc_host.new"

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
	// and it must not be expired or it can't be renewed
	if ((creds.times.endtime >= now) && ((creds.times.renew_till - now) > (10*60))) {
	  // yup. but keep searching in case there's more than one
	  // and another one is still current
	  found_tgt = TRUE;
	}
      }
      krb5_free_cred_contents(kcontext, &creds);
    }

    if (debug) {
      if (found_current_tgt) 
	mylog(LOG_DEBUG, "current ticket in %s", krb5_cc_get_name(kcontext, cache));
      else if (found_tgt)
	mylog(LOG_DEBUG, "renewable ticket in %s", krb5_cc_get_name(kcontext, cache));	
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

    code = krb5_cc_get_principal(ctx, ccache, &user);
    if (code != 0) {
      // file is probably empty. Can't renew if there's no principal
      mylog(LOG_ERR, "error reading ticket cache");
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
 * Make a new renewed cache in /tmp/krb5cc_NNN-renew
 * only renew if within minleft sec of expiration
 */
static krb5_error_code
newrenewed(krb5_context ctx, krb5_ccache ccache, time_t minleft, uid_t uid, struct uid_info *uident) {
    krb5_error_code code;
    krb5_principal user = NULL;
    krb5_creds creds;
    krb5_ccache ncache = NULL;
    int creds_valid = 0;
    char namebuf[1024];
    char *namecopy;

    if (uident->primary_cc) {
      mylog(LOG_ERR, "newrenewd called for %lu when there's already a copy", (unsigned long)uid);
    }

    snprintf(namebuf, sizeof(namebuf)-1, "/tmp/krb5cc_%lu-renew", (unsigned long)uid);

    memset(&creds, 0, sizeof(creds));

    code = krb5_cc_get_principal(ctx, ccache, &user);
    if (code != 0) {
      // file is probably empty. Can't renew if there's no principal
      mylog(LOG_ERR, "error reading ticket cache");
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
    
    mylog(LOG_DEBUG, "copying renewed cache %s to %s", krb5_cc_get_name(ctx, ccache), namebuf);

    code = krb5_cc_resolve(ctx, namebuf, &ncache);
    if (code != 0) {
      mylog(LOG_ERR, "can't open cache %s %s", namebuf, error_message(code));
      goto done;
    }

    code = krb5_cc_initialize(ctx, ncache, user);
    if (code != 0) {
      mylog(LOG_ERR, "error initializing cache %s", error_message(code));
      goto done;
    }
    code = krb5_cc_store_cred(ctx, ncache, &creds);
    if (code != 0) {
      mylog(LOG_ERR, "error storing credentials %s", error_message(code));
      goto done;
    }

    // worked. record that we've made a copy
    namecopy = malloc(strlen(namebuf) + 1);
    strcpy(namecopy, namebuf);
    uident->primary_cc = namecopy;

done:
    if (user != NULL)
      krb5_free_principal(ctx, user);
    if (creds_valid)
      krb5_free_cred_contents(ctx, &creds);
    if (ncache)
      krb5_cc_close(ctx, ncache);
    return code;
}

/* 
 * renew all cc's for one uid
 * both their primary in KEYRING and things in /tmp
 */ 

struct dirent **namelist;
int numdirs;

static void
renewpass1(krb5_context kcontext, uid_t uid, time_t minleft, struct uid_info *uident) {
  krb5_error_code code;
  krb5_ccache cache = NULL;
  char namebuf[1024];
  char tempnamebuf[1024];
  regex_t regex;
  char regbuf[100];
  int i;
  struct stat statbuf;

  snprintf(namebuf, sizeof(namebuf)-1, "KEYRING:persistent:%lu", (unsigned long)uid);

  // get primary cache for this user
  krb5_cc_set_default_name(kcontext, namebuf);
  code = krb5_cc_default(kcontext, &cache);
  if (code != 0) {
    mylog(LOG_ERR, "can't get default cache %s", error_message(code));
    goto done;
  }

  if (debug > 1)
    mylog(LOG_ERR, "Considering primary %lu", (unsigned long)uid);

  if (needs_renew(kcontext, cache, minleft)) {
    // if this the first renewal for this user, create the temporary cache
    if (!uident->primary_cc)
      newrenewed(kcontext, cache, minleft, uid, uident);
    renew(kcontext, cache, minleft);
  }

  krb5_cc_close(kcontext, cache);
  cache = NULL;

  // now look in /tmp

  //  /tmp/krb5cc_1044 or /tmp/krb5cc_1044_foo
  snprintf(regbuf, sizeof(regbuf)-1, "^krb5cc_%lu\\(_\\|$\\)", (unsigned long)uid);

  if(regcomp(&regex, regbuf, 0)) {
    mylog(LOG_ERR, "Couldn't compile regex %s", regbuf);
    goto done;
  }

  for (i = 0; i < numdirs; i++) {

    // only look at directories matching the pattern
    if (regexec(&regex, namelist[i]->d_name, 0, NULL, 0))
      continue;

    snprintf(tempnamebuf, sizeof(tempnamebuf)-1, "/tmp/%s", namelist[i]->d_name);

    if (debug > 1)
      mylog(LOG_ERR, "Considering %s", tempnamebuf);

    if (stat(tempnamebuf, &statbuf)) {
      // file went away?
      mylog(LOG_ERR, "can't get default cache %s", error_message(code));
      continue;
    }
    
    if (!S_ISREG(statbuf.st_mode)) {
      continue;
    }

    // only look at files owned by this user
    if (statbuf.st_uid != uid) {
      continue;
    }

    code = krb5_cc_resolve(kcontext, tempnamebuf, &cache);
    if (code) {
      mylog(LOG_ERR, "can't resolve %s %s", tempnamebuf, error_message(code));      
      if (cache)
	krb5_cc_close(kcontext, cache);
      cache = NULL;
      continue;
    }
			   
    if (needs_renew(kcontext, cache, minleft)) {
      // if this the first renewal for this user, create the temporary cache
      if (!uident->primary_cc)
	newrenewed(kcontext, cache, minleft, uid, uident);
      renew(kcontext, cache, minleft);
    }

    krb5_cc_close(kcontext, cache);
    cache = NULL;
  }

  regfree(&regex);

 done:
  if (cache)
    krb5_cc_close(kcontext, cache);

}

/*
 * Renew the primary entry. It's no longer primary
 */
krb5_error_code
  renewpass2(krb5_context ctx, uid_t uid, time_t minleft, struct uid_info *uident) {

    // nothing to do
    if (!uident->primary_cc)
      return 0;

    // delete the temp file
    mylog(LOG_DEBUG, "Removing %s", uident->primary_cc);
    unlink(uident->primary_cc);

    return 0;
}

#ifdef UNDEF
// code not currently used

/*
 * Maintain /tmp/krb5_cc_anon
 */
static krb5_error_code
checkanonymous(krb5_context ctx, time_t minleft) {
    krb5_error_code code;
    krb5_ccache ccache = NULL;
    krb5_ccache ncache = NULL;
    krb5_principal user = NULL;
    krb5_creds creds;
    int creds_valid = 0;
    char *realm = NULL;
    krb5_creds usercreds;
    int credsused = 0;
    krb5_keytab userkeytab;
    krb5_get_init_creds_opt *options;
    krb5_kt_cursor ktcursor;
    krb5_keytab_entry ktentry;

    memset(&creds, 0, sizeof(creds));

    ccache = NULL;
    code = krb5_cc_resolve(ctx, ANONCC, &ccache);
    if (code) {
      mylog(LOG_ERR, "error resolving %s %s", ANONCC, error_message(code));
      goto done;
    }

    // if we have a cache and it doesn't need renewing, exit
    if ((code = krb5_cc_get_principal(ctx, ccache, &user)) == 0 &&
	!needs_renew(ctx, ccache, minleft)) {	
      mylog(LOG_DEBUG, "anonymous cache OK");
      goto done;
    }

    if (user != NULL)
      krb5_free_principal(ctx, user);

    if (ccache)
      krb5_cc_close(ctx, ccache);    

    mylog(LOG_DEBUG, "renewing principal cache %s", ANONCC);

    // this one is in /tmp. To minimize race conditions, creata a new version and rename it onto the real name

    // we need a principal. Get the first one from /etc/krb5.keytab
    // that's normally host/xxx. At any rate it should have a good random key

    if ((code = krb5_kt_resolve(ctx, HOSTKT, &userkeytab))) {
      mylog(LOG_ERR, "unable to get keytab from %s %s", HOSTKT, error_message(code));
      goto done;
    }

    if ((code = krb5_kt_start_seq_get(ctx, userkeytab, &ktcursor))) {
      mylog(LOG_ERR, "unable to get cursor for keytab from %s %s", HOSTKT, error_message(code));
      goto done;
    }

    if ((code = krb5_kt_next_entry(ctx, userkeytab, &ktentry, &ktcursor))) {
      krb5_kt_end_seq_get(ctx, userkeytab, &ktcursor);
      goto done;
    }

    // copy the principal so we can free the entry
    if ((code = krb5_copy_principal(ctx, ktentry.principal, &user))) {
      mylog(LOG_ERR, "unable to copy principal from key table %s", error_message(code));
    }

    if ((code = krb5_free_keytab_entry_contents(ctx, &ktentry))) {
      mylog(LOG_ERR, "unable to free entry for keytab from %s %s", HOSTKT, error_message(code));
    }

    if ((code = krb5_kt_end_seq_get(ctx, userkeytab, &ktcursor))) {
      mylog(LOG_ERR, "unable to end cursor for keytab from %s %s", HOSTKT, error_message(code));
    }

    // get rid of any leftover temp files
    // there's clearly a race condition here, but I'm assuming only one
    // copy of renewd will be running.
    unlink(ANONCCTEMPNAME);
    // create temp one
    code = krb5_cc_resolve(ctx, ANONCCTEMPNAME, &ccache);
    if (code) {
      mylog(LOG_ERR, "error resolving %s %s", ANONCC, error_message(code));
      goto done;
    }

    code = krb5_cc_initialize(ctx, ccache, user);
    if (code != 0) {
      mylog(LOG_ERR, "error reinitializing cache %s", error_message(code));
      goto done;
    }

    if ((code = krb5_get_init_creds_opt_alloc(ctx, &options))) {
      mylog(LOG_ERR, "unable to allocate options %s", error_message(code));
      goto done;
    }

    if ((code = krb5_get_init_creds_keytab(ctx, &usercreds, user, userkeytab, 0,  NULL, options))) {
      mylog(LOG_ERR, "unable to make credentials for ANONYMOUS from keytab %s", error_message(code));
      goto done;
    }

    credsused = 1;

    code = krb5_cc_store_cred(ctx, ccache, &usercreds);
    if (code != 0) {
      mylog(LOG_ERR, "error storing credentials %s", error_message(code));
      goto done;
    }

    krb5_cc_close(ctx, ccache);    
    ccache = NULL;

    // make sure this is protected. It has a session key that could be
    // used to spy on a user's login. Since root could use a keylogger,
    // we think restricting it to root as about as good as we can do.
    code = chmod(ANONCCTEMP, 0600);
    if (code) {
      mylog(LOG_ERR, "unable to make new anonymous creds public %m");
      goto done;
    }

    // rename it to real name
    code = rename(ANONCCTEMP, ANONCC);
    if (code) {
      mylog(LOG_ERR, "unable to put new anonymous creds in place %m");
      goto done;
    }

    mylog(LOG_DEBUG, "new anonymous cache created");

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
    if (realm)
      krb5_free_default_realm(ctx, realm);
    if (userkeytab)
      krb5_kt_close(ctx, userkeytab);
    if (options)
      krb5_get_init_creds_opt_free(ctx, options);
    if (credsused)
      krb5_free_cred_contents(ctx, &usercreds);

    return code;
}

#endif


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
	  // need a new entry
	  struct uid_info *new_entry = malloc(sizeof(struct uid_info));
	  // point to previous entry in the list
	  new_entry->next_item = uidlist;
	  new_entry->primary_cc = NULL;
	  new_entry->key = malloc(strlen(uidbuf) + 1);
	  strcpy(new_entry->key, uidbuf);

	  uident.key = new_entry->key;
	  uident.data = (void *)new_entry;

	  // this is now the new tail of the list
	  uidlist = new_entry;
	  // need to save the entry so we can free it
	  new_entry->entry = hsearch(uident, ENTER);

	}
      }
    }
  }
  closedir(procdir);
}

// free malloced uids from hash
void freeuids() {
  while (uidlist) {
    struct uid_info *next = uidlist->next_item;
    free(uidlist->key);
    if (uidlist->primary_cc)
      free(uidlist->primary_cc);
    //    free(uidlist->entry);
    free(uidlist);
    uidlist = next;
  }
  hdestroy();
}

// go through all uids that are active and renew the primary cache for that uid if necessary
void renewallpass1(krb5_context ctx, time_t minleft) {
  struct uid_info *uident = uidlist;
  int i;

  numdirs = scandir("/tmp", &namelist, NULL, alphasort);
  if (numdirs < 0) {
    mylog(LOG_ERR, "Couldn't scan /tmp");
    namelist = NULL;
  }

  while (uident) {
    uid_t uid;
    uid = atol(uident->key);
    seteuid(uid);
    renewpass1(ctx, uid, minleft, uident);
    seteuid(0L);
    uident = uident->next_item;
  }

  if (namelist) {
    for (i = 0; i < numdirs; i++) {
      free(namelist[i]);
    }
    free(namelist);
  }

}

// go through all uids that are active:
// check all caches
// if any except primary requires renewing, renew it
// if primary requires renewing, save it in the uident and make
//    another cache primary. if there is no other cache, create it

void renewallpass2(krb5_context ctx, time_t minleft) {
  struct uid_info *uident = uidlist;
  while (uident) {
    uid_t uid;
    uid = atol(uident->key);
    seteuid(uid);
    renewpass2(ctx, uid, minleft, uident);
    seteuid(0L);
    uident = uident->next_item;
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
  unsigned long wait = 50; // 50 min, for key lifetime of 60

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

    // checkanonymous(context, 60 * (wait + 10));

    mylog(LOG_DEBUG, "main loop");

    getuids(); // put uids of all procs into the hash

    renewallpass1(context, 60 * (wait + 10));

    // wait 1 min for pass 2; deletes temporary caches

    sleep(60);

    // pass 2. renew all caches we didn't create

    mylog(LOG_DEBUG, "removing temporary caches");

    // See comments on renewall for why we use 6 rather than
    // 10 here.
    renewallpass2(context, 60 * (wait + 6));
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

