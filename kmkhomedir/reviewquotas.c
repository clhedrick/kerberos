// review all existing quotas and adjust them if necessary
// typically this is because users have changed group membership
// This is based on /etc/quotas.conf
//
// NOTE: the user ZFS commands use strings like '10.4G'. However
// internally quotas are 64-bit integers. That's the way we deal
// with them

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <regex.h>
#include <stdint.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/nvpair.h>
#include <libnvpair.h>
#include <libzfs.h>

#define MAXGROUPS 100
#define MAXMEMBERS 5000
#define MEMBERSIZE 10
//#define DEBUG 1

struct quotaspec {
  struct group *grp;
  // mallocted buffer for group, so it can be freed
  char *groupbuf;
  uint64_t amount;
  int isplus;
  int isdefault;
  struct quotaspec *next;
};

// args for callback
struct argb {
  struct quotaspec *qlist;
  zfs_handle_t *zh;
};

// called for each user with an existing quota on a file system
// this is where we look at current quota,
// compute desired quota from qlist in the arg, and update if necessary
//   arg is passed through from the zfs_userspace call. it has
//     info on the file system 
//   domain is irrelevant
//   rid is the uid of the user involved
//   space is their current quota
int us_callback(void *arg, const char*domain, uid_t rid, uint64_t space) {
    uint64_t base = 0L;
    uint64_t incr = 0L;
    int ngroups = 0;
    
    // get actual args out of the struct
    struct argb *argp = (struct argb *) arg;
    struct quotaspec *quotalist = argp->qlist;
    zfs_handle_t *zh = argp->zh;

    // rid is the user with the existing quota
    struct passwd* pw = getpwuid(rid);
    if(pw == NULL){
      return(0);
    }
    
    // now look at quota specs to compute desired
    // quota for this user
    // for quotas without +, pick the largest one for this user. That's base
    // incr is all quotas for the user with +, gets added to base
    struct quotaspec *q = quotalist;
    int found = 0;
    while (q) {
      if (q->isdefault == 1) {
	// default applies to everyone
	if (q->isplus)
	  incr += q->amount;
	else if (q->amount > base)
	  base = q->amount;
      } else {
	// the quota spec has a group. see if this person
	// is a member of the group
	char **userlist = q->grp->gr_mem;
	if (! userlist)
	  continue;
	// loop over all users in the group.
	// see if our person is one of them
	for (int i=0; userlist[i] != NULL; i++) {
	  if (strcmp(userlist[i], pw->pw_name) == 0) {
	    // yes, process the amount
	    if (q->isplus)
	      incr += q->amount;
	    else if (q->amount > base)
	      base = q->amount;
	    break;
	  }
	}
      }
      q = q->next;
    }

    // compute desired quota
    uint64_t desired = base + incr;
    // the current quota is in spae

#ifdef DEBUG    
    printf("domain %s rid %d spacde current %lu correct %lu\n", domain, rid, space, desired);
#endif

    // do we need to change the quota?
    if (space != desired) {
      char *quotaattr = NULL;
      char *quotastr = NULL;
      (void)asprintf(&quotaattr, "userquota@%s", pw->pw_name);
      // quotas internally are actually 64-bit integers
      (void)asprintf(&quotastr, "%lu", desired);
      printf("setting %s %s\n ", quotaattr, quotastr);
      zfs_prop_set(zh, quotaattr, quotastr);
    }

    return (0);
}

// we're looping through file systems in /etc/quotas.conf
// once we have all the info for a file system, call this
// to process it. this will loop over all users with quotas
// on the file system and update their quota
void procfs(libzfs_handle_t *libzh, char *dirname, char *filesys, struct quotaspec* quotalist) {
  // probably at end
  if (dirname == NULL && filesys == NULL && quotalist == NULL)
     return;
  if (dirname == NULL || filesys == NULL || quotalist == NULL) {
    fprintf(stderr, "incomplete section %s %s\n", dirname?dirname:"", filesys?filesys:"");
    exit(1);
  }

  // open the file system
  zfs_handle_t *zh = zfs_open(libzh, filesys, ZFS_TYPE_FILESYSTEM);
  if (!zh) {
    fprintf(stderr, "not able to open file system %s\n", filesys);
    exit(1);
  }

  // for debugging, print the quota specifications for this file system
#ifdef DEBUG    
  printf("\ndir %s fs %s\n", dirname, filesys);
  struct quotaspec *qq = quotalist;
  while(qq) {
    printf("group %s plus %d amount %lu\n", qq->isdefault?"default":qq->grp->gr_name, qq->isplus, qq->amount);
    qq = qq->next;
  }
#endif

  // callback can only take one argument, so we have to
  // package the actual arguments into a struct
  struct argb argb;
  argb.qlist = quotalist;
  argb.zh = zh;

  // loop over all users with existing quotas on this file system
  // calls us_callback for each one, passing the quota info
  // and argb
  zfs_userspace(zh, ZFS_PROP_USERQUOTA, us_callback, &argb);

  zfs_close(zh);

}

int main(int argc, char *argv[]) {
  char propbuf[1024];
  regex_t section_pat;
  regex_t valid_section_pat;
  regex_t fs_pat;
  regex_t data_pat;
  regex_t skip_pat;

  if (regcomp(&section_pat, "^[ \t]*\\[", REG_NOSUB) != 0) {
    fprintf(stderr, "Can't compile section_pat");
    exit(1);
  }
  //  if (regcomp(&valid_section_pat, "^[ \t]*\\[[ \t]*([-a-zA-Z/0-9_]+)[ \t]*\\]", REG_NEWLINE) != 0) {
  if (regcomp(&valid_section_pat, "^[ \t]*\\[[ \t]*([-a-zA-Z/0-9_]+)[ \t]*\\]", REG_EXTENDED|REG_NEWLINE) != 0) {
    fprintf(stderr, "Can't compile valid_section_pat");
    exit(1);
  }
  if (regcomp(&fs_pat, "^[ \t]*fs[ \t]*=[ \t]*([-a-zA-Z/0-9_+]+)[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
    fprintf(stderr, "Can't compile fs_pat");
    exit(1);
  }
  if (regcomp(&data_pat, "^[ \t]*([-a-zA-Z/0-9_]+)[ \t]*=[ \t]*(\\+?)[ \t]*([0-9a-zA-Z.]+)[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
    fprintf(stderr, "Can't compile data_pat");
    exit(1);
  }
  if (regcomp(&skip_pat, "^[ \t]*#|^[ \t\n]*$", REG_EXTENDED|REG_NOSUB) != 0) {
    fprintf(stderr, "Can't compile skip_pat");
    exit(1);
  }

  // go through conf file
  // for each section, parse all the group specificatios,
  // and then check all users with quotas on that file system

  // one-time initialization for ZFS. Have to pass this around
  // because all ZFS calls need it
  libzfs_handle_t *libh = libzfs_init();

  FILE *cf = fopen("/etc/quotas.conf", "r");
  if (!cf) {
    fprintf(stderr, "unable to open /etc/quotas.conf");
    exit(1);
  }

  // first section to match
  char *line = NULL;
  size_t len = 0;
  
  // directory we're in. Not actually used in this program
  char * dirname = NULL;
  // corresponding ZFS file system
  char * filesys = NULL;
  // list of quota specs for this file system
  // this is basically the line from file, digested a bit
  struct quotaspec * quotalist = NULL;
  struct quotaspec * quotalast = NULL;

  while (getline(&line, &len, cf) != -1) {
    regmatch_t match[5];

    int ret;

    // skip comments
    if (regexec(&skip_pat, line, 0, NULL, 0) == 0)
      continue;

    // see if it's close enough to a section to close off previous one
    ret = regexec(&section_pat, line, 2, match, 0);

    // yes, we're no longer in a previous section
    if (ret == 0) {
      // in new section
      ret = regexec(&valid_section_pat, line, 2, match, 0);
      if (ret != 0) {
	// could skip the section, but it would complicate
	// the code, and might as well get it fixed
	fprintf(stderr, "Bad section header %s, exiting\n", line);
	exit(1);
      }
      
      // have a valid section header. Process previous section.
      // do it here because until now we don't have all the data
      // for the section. Will also have to do it at the end for
      // the last section.

      // loop over all existing quotas for this file system and fix them
      procfs(libh, dirname, filesys, quotalist);

      // free stuff from last time
      if (dirname) {
	free(dirname);
	dirname = NULL;
      }
      if (filesys) {
	free(filesys);
	filesys = NULL;
      }
      // free the list
      struct quotaspec *q = quotalist;
      while (q) {
	struct quotaspec *next = q->next;
	if (q->grp) {
	  if (q->groupbuf)
	    free(q->groupbuf);
	  free(q->grp);
	}
	free(q);
	q = next;
      }
      quotalist = NULL;
      quotalast = NULL;

      // get the section name
      char *name = line + match[1].rm_so;
      // terminate with nul
      line[match[1].rm_eo] = '\0';
      dirname = strdup(name);
      // done with this line
      continue;
    }
	
    // not a section header

    // first special case: fs=
    ret = regexec(&fs_pat, line, 2, match, 0);
    if (ret == 0) {
      char *value;

      // fs=name is the ZFS file system
      // save it in filesys
      value = line + match[1].rm_so;
      // terminate with nul
      line[match[1].rm_eo] = '\0';

      // if more than one first wins
      if (!filesys) {
	filesys = strdup(value);
      }

      // done with this line
      continue;
    }

    // better be a quota specification
    ret = regexec(&data_pat, line, 5, match, 0);
    if (ret != 0) {
      fprintf(stderr, "bad quota specification line: %s\n", line);
      exit(1);
    }

    // now we have a valid specification. Parse it. It goes into
    // a quotaspec struct

    struct quotaspec *q = calloc(1, sizeof(struct quotaspec));

    // line is "group=quota". get the group
    // (Can also be "default")
    char *attr = line + match[1].rm_so;
    // terminate with nul
    line[match[1].rm_eo] = '\0';

    if (strcmp(attr, "default") == 0) {
      q->isdefault = 1;
    } else {
      // it's a group. we need to save the whole group struct so we
      // can see if the user is in the group
      
      // allocate group data structure on heap, since getgrnam reuses
      // static memory. Need to save the buffer so we can free it
      char *groupbuf = malloc(MAXMEMBERS * MEMBERSIZE);
      struct group *group = malloc(sizeof(struct group));
      struct group *grp; // will get either NULL or group
      int groupret = getgrnam_r(attr, group, groupbuf, MAXMEMBERS * MEMBERSIZE, &grp);
      if (groupret != 0) {
	// this does not include group not found. That returns zero
	// with NULL result.
	fprintf(stderr, "getgrname_t failed %s\n", attr);
	exit(1);
      }
      if (!grp) {
	fprintf(stderr, "nonexistent or nonposix group: %s\n", attr);
	exit(1);
      }
      q->grp = grp;
      q->groupbuf = groupbuf;
    }
    
    // have processed the group or default. Now process the quota
    // can be group=10g or group=+10g. See if it's a plus
    if (line[match[2].rm_so] == '+')
      q->isplus = 1;

    // quota specification can be number of something like 10G
    // ZFS has a library routine to parse this.
    char *num = line + match[3].rm_so;
    // terminate with nul
    line[match[3].rm_eo] = '\0';
    // ask ZFS to parse specification. Output is a 64-bit integer
    // put it in the "amount" field of the quotaspec
    int i = zfs_nicestrtonum(libh, num, &q->amount);
    if (i != 0) {
      fprintf(stderr, "bad quota spec %s\n", line);
      exit(1);
    }

    // put this quota spec into the list at the end
    if (quotalast)
      quotalast->next = q;
    else
      quotalist =  q;
    quotalast = q;

  }
  // process last group
  procfs(libh, dirname, filesys, quotalist);


  fclose(cf);

}
