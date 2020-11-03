// review all existing quotas and adjust them if necessary
// typically this is because users have changed group membership
// This is based on /etc/quotas.conf
//
// NOTE: the user ZFS commands use strings like '10.4G'. However
// internally quotas are 64-bit integers. That's the way we deal
// with them

// this module is almost identical to the ZFS version. 
// it understands quotas, parsing the file and figuring out
// the quota for a single user.

// For efficienty, it parss the file once, builing a list of
// the lines in the file. It then interprets the list for each user

// netapp.c has the code to go through all users. It is equivalent
// tto zfs_space. It calls back to this module for each user to 
// compute the quota and see if anything should change. In ZFS,
// zfs_space has a callback, so the structure is the same

// postinmemory is the code to set a quota. With ZFS it's a couple of
// library calls, but here there's enough boilerplate that it's worth
// keeping separate.

// ZFS has a function to parse space specifiations, e.g. 10g. Since
// this program runs on systems without libzfs, I've done my own
// implementation. It's nearly identical. See parsesize.c

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

#define MAXGROUPS 100
#define MAXMEMBERS 5000
#define MEMBERSIZE 10
//#define DEBUG 1

int test = 0;

#define GETMATCH(l,m,off) (l[m[off].rm_eo] = '\0', l + m[off].rm_so)

extern int change_quota(const char *uuid, long quota, char *vol, char *qtree, const char *username);

// NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE
// ZFS does not have soft quotas, and we're not using
// them for the Netapp. So we ignore the soft quota spec
// in the file. THe file format and parser support them.
// (That was probably a mistake. At the time it looked
// like we were using soft quotas on the Netapp.)

// Build a list of these specifications, one per line of
// the quotas file. That way the per-user code can compute
// the quota for a user. It's faster this way than reading
// the file for each user.

struct quotaspec {
  struct group *grp;
  // mallocted buffer for group, so it can be freed
  char *groupbuf;
  uint64_t amount;
  int isplus;
  int isdefault;
  int isnone;
  char *user;
  struct quotaspec *next;
};

// called for each user with an existing quota on a file system
// also for new users.
// You can tell these apart by the UUID. If there's a UUID it's
//   an existing entry.
// this is where we look at current quota,
// compute desired quota from qlist in the arg, and update if necessary
//   arg is passed through from the zfs_userspace call. it has
//     info on the file system 
//   domain is irrelevant
//   rid is the uid of the user involved
//   space is their current quota
int us_callback(struct quotaspec *quotalist, const char *uuid, const char *username, long space, char *vol, char *qtree) {
    uint64_t base = 0L;
    uint64_t incr = 0L;
    int ngroups = 0;
    // none is a flag. if any entry that applies
    // to this user says "none", this user has
    // no quota, i.e. infinite quota. With netapp, it's represented as zero
    int none = 0;

    // now look at quota specs to compute desired
    // quota for this user
    // for quotas without +, pick the largest one for this user. That's base
    // incr is all quotas for the user with +, gets added to base
    struct quotaspec *q = quotalist;
    int found = 0;
    while (q) {
      if (q->user) {
	// if our user has a user entry, use that, without
	// bothering with defaults or groups
	if (strcmp(q->user, username) == 0) {
	  // for user, use this exact amount
	  base = q->amount;
	  incr = 0L;
	  none = q->isnone;
	  break;
	}
	// finished with this spec
	// will fall through to next iteration
      } else if (q->isdefault == 1) {
	// default applies to everyone
	// a lot of these combinaions make no sense
	// with a default quota. It's very unlikely
	// that the default will be "none" or use +
	if (q->isnone)
	  none = 1;
	else if (q->isplus)
	  incr += q->amount;
	else if (q->amount > base)
	  base = q->amount;
      } else {
	// the quota spec has a group. see if this person
	// is a member of the group
	char **userlist = q->grp->gr_mem;
	if (userlist) {
	  int i;
	  // loop over all users in the group.
	  // see if our person is one of them
	  for (i=0; userlist[i] != NULL; i++) {
	    if (strcmp(userlist[i], username) == 0) {
	      // yes, process the amount
	      if (q->isnone)
		none = 1;
	      else if (q->isplus)
		incr += q->amount;
	      else if (q->amount > base)
		base = q->amount;
	      break;
	    }
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

    // netapp uses 0 for no quota
    if (none)
      desired = -1L;

    // do we need to change the quota?

    // for a new entry, caller passes Netapp's default quota as "space". So
    // we won't create a quota entry if the correct quota is Netapp's default.
    // At the moment Netapp's default is also the default in /etc/quotas.conf,
    // but that need not be the case
    if (space != desired) {
      if (uuid)
	printf("change %lu to %lu for %s\n", space, desired, username);
      else
	printf("add %lu %lu for %s\n", space, desired, username);
      if (!test)
	change_quota(uuid, desired, vol, qtree, username);
      // without a delay, the netapp gives errors
      sleep(3);
    }

    return (0);
}

// NOTE
// We can process multiple file systems
// So we read each section of the quota file
// and the call procfs with the parsed quota
// entries, to process that file system.

int main(int argc, char *argv[]) {
  char propbuf[1024];
  regex_t section_pat;
  regex_t valid_section_pat;
  regex_t qtree_pat;
  regex_t vol_pat;
  regex_t data_pat;
  regex_t skip_pat;

  if ((argc > 1) && strcmp(argv[1], "-t") == 0)
    test = 1;

  if (regcomp(&section_pat, "^[ \t]*\\[", REG_NOSUB) != 0) {
    fprintf(stderr, "Can't compile section_pat");
    exit(1);
  }
  //  if (regcomp(&valid_section_pat, "^[ \t]*\\[[ \t]*([-a-zA-Z/0-9_]+)[ \t]*\\]", REG_NEWLINE) != 0) {
  if (regcomp(&valid_section_pat, "^[ \t]*\\[[ \t]*([-a-zA-Z/0-9_]+)[ \t]*\\]", REG_EXTENDED|REG_NEWLINE) != 0) {
    fprintf(stderr, "Can't compile valid_section_pat");
    exit(1);
  }
  if (regcomp(&qtree_pat, "^[ \t]*:qtree[ \t]*=[ \t]*([-a-zA-Z/0-9_+]+)[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
    fprintf(stderr, "Can't compile fs_pat");
    exit(1);
  }
  if (regcomp(&vol_pat, "^[ \t]*:vol[ \t]*=[ \t]*([-a-zA-Z/0-9_+]+)[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
    fprintf(stderr, "Can't compile fs_pat");
    exit(1);
  }
  if (regcomp(&data_pat, "^[ \t]*(@?)(:?[-a-zA-Z/0-9_]+)[ \t]*=[ \t]*(\\+?)[ \t]*([0-9a-zA-Z.]+)([ \t]*([0-9a-zA-Z.]+))?[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
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
  // corresponding Netapp file system
  char * qtree = NULL;
  char * vol = NULL;
  // list of quota specs for this file system
  // this is basically the line from file, digested a bit
  struct quotaspec * quotalist = NULL;
  struct quotaspec * quotalast = NULL;

  while (getline(&line, &len, cf) != -1) {
    regmatch_t match[8];

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
      procfs(dirname, vol, quotalist, qtree);

      // free stuff from last time
      if (dirname) {
	free(dirname);
	dirname = NULL;
      }
      if (qtree) {
	free(qtree);
	qtree = NULL;
      }
      if (vol) {
	free(vol);
	vol = NULL;
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
	if (q->user)
	  free(q->user);
	free(q);
	q = next;
      }
      quotalist = NULL;
      quotalast = NULL;

      // get the section name
      dirname = strdup(GETMATCH(line,match,1));
      // done with this line
      continue;
    }
	
    // not a section header

    // first special case: qtree=
    ret = regexec(&qtree_pat, line, 2, match, 0);
    if (ret == 0) {
      // fs=name is the ZFS file system
      char *value = GETMATCH(line,match,1);

      // if more than one first wins
      if (!qtree) {
	qtree = strdup(value);
      }

      // done with this line
      continue;
    }

    // first special case: vol=
    ret = regexec(&vol_pat, line, 2, match, 0);
    if (ret == 0) {
      // fs=name is the ZFS file system
      char *value = GETMATCH(line,match,1);

      // if more than one first wins
      if (!vol) {
	vol = strdup(value);
      }

      // done with this line
      continue;
    }

    // better be a quota specification
    ret = regexec(&data_pat, line, 8, match, 0);
    if (ret != 0) {
      fprintf(stderr, "bad quota specification line: %s\n", line);
      exit(1);
    }

    // now we have a valid specification. Parse it. It goes into
    // a quotaspec struct

    struct quotaspec *q = calloc(1, sizeof(struct quotaspec));

    // line is "group=quota". get the group
    // (Can also be "default")
    char *attr = GETMATCH(line, match, 2);
    int isgroup = 0;

    if (line[match[1].rm_so] == '@')
      isgroup = 1;

    if (strcmp(attr, ":default") == 0) {
      q->isdefault = 1;
    } else if (isgroup){
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
    } else {
      // is not @group it's a user
      q->user = strdup(attr);
    }
    
    // have processed the group or default. Now process the quota
    // can be group=10g or group=+10g. See if it's a plus
    if (line[match[3].rm_so] == '+')
      q->isplus = 1;

    // quota specification can be number of something like 10G
    // ZFS has a library routine to parse this.
    char *num = GETMATCH(line,match,4);

    // ask ZFS to parse specification. Output is a 64-bit integer
    // put it in the "amount" field of the quotaspec
    if (strcmp(num, "none") == 0)
      q->isnone = 1;
    else {
      int i = zfs_nicestrtonum(NULL, num, &q->amount);
      if (i != 0) {
	fprintf(stderr, "bad quota spec %s\n", line);
	exit(1);
      }
    }

    // put this quota spec into the list at the end
    if (quotalast)
      quotalast->next = q;
    else
      quotalist =  q;
    quotalast = q;

  }
  // process last group
  procfs(dirname, vol, quotalist, qtree);

  if (line)
    free(line);

  // free stuff from last time
  if (dirname) {
    free(dirname);
    dirname = NULL;
  }
  if (qtree) {
    free(qtree);
    qtree = NULL;
  }
  if (vol) {
    free(vol);
    vol = NULL;
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
    if (q->user)
      free(q->user);
    free(q);
    q = next;
  }

  fclose(cf);

  regfree(&section_pat);
  regfree(&valid_section_pat);
  regfree(&qtree_pat);
  regfree(&vol_pat);
  regfree(&data_pat);
  regfree(&skip_pat);


}
