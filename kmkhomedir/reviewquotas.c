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


struct quotaspec {
  gid_t gid;
  uint64_t amount;
  int isplus;
  struct quotaspec *next;
};

struct argb {
  struct quotaspec *qlist;
  zfs_handle_t *zh;
};

int us_callback(void *arg, const char*domain, uid_t rid, uint64_t space) {
    uint64_t base = 0L;
    uint64_t incr = 0L;
    int ngroups = 0;
    
    struct argb *argp = (struct argb *) arg;
    struct quotaspec *quotalist = argp->qlist;
    zfs_handle_t *zh = argp->zh;

    struct passwd* pw = getpwuid(rid);
    if(pw == NULL){
      return(0);
    }
    
    // need user's groups so we can pick the right quota
    //this call is just to get the correct ngroups
    getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups);

  __gid_t groups[ngroups];

    getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);

    struct quotaspec *q = quotalist;
    int found = 0;
    while (q) {
      if (q->gid == 0) {
	if (q->isplus)
	  incr += q->amount;
	else if (q->amount > base)
	  base = q->amount;
      } else {
	for (int i=0; i < ngroups; i++) {
	  if (groups[i] == q->gid) {
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

    uint64_t desired = base + incr;

    printf("domain %s rid %d spacde current %lu correct %lu\n", domain, rid, space, desired);

    if (space != desired) {
      char *quotaattr = NULL;
      char *quotastr = NULL;
      (void)asprintf(&quotaattr, "userquota@%s", pw->pw_name);
      (void)asprintf(&quotastr, "%lu", desired);
      printf("setting %s %s\n ", quotaattr, quotastr);
      zfs_prop_set(zh, quotaattr, quotastr);
    }

    return (0);
}

void procfs(libzfs_handle_t *libzh, char *dirname, char *filesys, struct quotaspec* quotalist) {
  // probably at end
  if (dirname == NULL && filesys == NULL && quotalist == NULL)
     return;
  if (dirname == NULL || filesys == NULL || quotalist == NULL) {
    fprintf(stderr, "incomplete section %s %s\n", dirname?dirname:"", filesys?filesys:"");
    exit(1);
  }

  zfs_handle_t *zh = zfs_open(libzh, filesys, ZFS_TYPE_FILESYSTEM);

  printf("dir %s fs %s\n", dirname, filesys);
  struct quotaspec *qq = quotalist;
  while(qq) {
    printf("group %u plus %d amount %lu\n", qq->gid, qq->isplus, qq->amount);
    qq = qq->next;
  }

  struct argb argb;
  argb.qlist = quotalist;
  argb.zh = zh;

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
  // and then check all the directories in that file system

  libzfs_handle_t *libh = libzfs_init();

  FILE *cf = fopen("/etc/quotas.conf", "r");
  if (!cf) {
    fprintf(stderr, "unable to open /etc/quotas.conf");
    exit(1);
  }

  // first section to match
  char *line = NULL;
  size_t len = 0;
  
  // directory we're in. look at all directories right under this
  char * dirname = NULL;
  // corresponding ZFS file system
  char * filesys = NULL;
  // list of quota specs
  struct quotaspec * quotalist = NULL;
  struct quotaspec * quotalast = NULL;

  // look for [....] with whitespace allowed
  while (getline(&line, &len, cf) != -1) {
    regmatch_t match[5];

    int ret;

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

    // we're in the right section, process data
    // first special case: fs
    ret = regexec(&fs_pat, line, 2, match, 0);
    if (ret == 0) {
      char *value;

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

    // now we have a valid specification. Parse it.

    struct quotaspec *q = calloc(1, sizeof(struct quotaspec));

    char *attr = line + match[1].rm_so;
    // terminate with nul
    line[match[1].rm_eo] = '\0';

    if (strcmp(attr, "default") == 0) {
      q->gid = 0;
    } else {
      struct group *gr = getgrnam(attr);
      if (!gr) {
	fprintf(stderr, "nonexistent or nonposix group: %s\n", attr);
      }
      q->gid = gr->gr_gid;
    }
    
    if (line[match[2].rm_so] == '+')
      q->isplus = 1;

    char *num = line + match[3].rm_so;
    // terminate with nul
    line[match[3].rm_eo] = '\0';
    int i = zfs_nicestrtonum(libh, num, &q->amount);
    if (i != 0) {
      fprintf(stderr, "bad quota spec %s\n", line);
      exit(1);
    }

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
