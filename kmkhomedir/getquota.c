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
#define ERRQUOTA NULL

char * getuserquota(libzfs_handle_t *hdl, char *filesys, char *user, char **fsret){
  FILE* cf;
  static char *line;
  size_t len;
  size_t count;
  int insection = 0;
  char *fs = NULL;
  uint64_t base = 0L;
  uint64_t incr = 0L;
  int ngroups = 0;

  regex_t section_pat;
  regex_t valid_section_pat;
  regex_t fs_pat;
  regex_t data_pat;
  regex_t skip_pat;

  //  gid_t groups[MAXGROUPS];

  struct passwd* pw = getpwnam(user);
  if(pw == NULL){
    syslog(LOG_ERR, "Can't use pw entry for %s", user);
    return(ERRQUOTA);
  }

  // need user's groups so we can pick the right quota
  
  //this call is just to get the correct ngroups
  getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups);

  __gid_t groups[ngroups];

  //here we actually get the groups
  getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups);

  if (regcomp(&section_pat, "^[ \t]*\\[", REG_NOSUB) != 0) {
        syslog(LOG_ERR, "Can't compile section_pat");
        return(ERRQUOTA);
  }
  //  if (regcomp(&valid_section_pat, "^[ \t]*\\[[ \t]*([-a-zA-Z/0-9_]+)[ \t]*\\]", REG_NEWLINE) != 0) {
  if (regcomp(&valid_section_pat, "^[ \t]*\\[[ \t]*([-a-zA-Z/0-9_]+)[ \t]*\\]", REG_EXTENDED|REG_NEWLINE) != 0) {
        syslog(LOG_ERR, "Can't compile valid_section_pat");
        return(ERRQUOTA);
  }
  if (regcomp(&fs_pat, "^[ \t]*fs[ \t]*=[ \t]*([-a-zA-Z/0-9_+]+)[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
        syslog(LOG_ERR, "Can't compile fs_pat");
        return(ERRQUOTA);
  }
  if (regcomp(&data_pat, "^[ \t]*([-a-zA-Z/0-9_]+)[ \t]*=[ \t]*(\\+?)[ \t]*([0-9a-zA-Z.]+)[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
        syslog(LOG_ERR, "Can't compile data_pat");
        return(ERRQUOTA);
  }
  if (regcomp(&skip_pat, "^[ \t]*#|^[ \t\n]*$", REG_EXTENDED|REG_NOSUB) != 0) {
        syslog(LOG_ERR, "Can't compile skip_pat");
        return(ERRQUOTA);
  }


  cf = fopen("/etc/quotas.conf", "r");
  if (!cf) {
    syslog(LOG_ERR, "unable to open /etc/quotas.conf");
    return(ERRQUOTA);
  }

  // first section to match
  line = NULL;
  len = 0;
  
  // look for [....] with whitespace allowed
  while ((count = getline(&line, &len, cf)) != -1) {
    regmatch_t match[5];
    int ret;

    //    printf("%d %s\n", regexec(&section_pat, line, 0, NULL, 0), line);
    //    printf("%d %s\n", regexec(&valid_section_pat, line, 2, match, 0), line);
    //    printf("   %d %d %d %d\n", match[0].rm_so, match[0].rm_eo, match[1].rm_so, match[1].rm_eo);
    //    printf("%d %s\n", regexec(&data_pat, line, 3, match, 0), line);
    //    printf("   %d %d %d %d %d %d\n", match[0].rm_so, match[0].rm_eo, match[1].rm_so, match[1].rm_eo, match[2].rm_so, match[2].rm_eo);
    
    // see if it's close enough to a section to close off previous one
    ret = regexec(&valid_section_pat, line, 2, match, 0);
    // yes, we're no longer in a previous section
    if (ret == 0) {
      // if we were in the right section, we're done
      if (insection)
	break;

      // not in the right section. see if this is it
      ret = regexec(&valid_section_pat, line, 2, match, 0);
      if (ret == 0) {
	// yup, get the section name
	char *name = line + match[1].rm_so;
	// terminate with nul
	line[match[1].rm_eo] = '\0';

	if (strncmp(name, filesys, strlen(name)) == 0  ) {
	  // match. this is the right section
	  // set the variable and look at the data
	  insection = 1;
	  continue;
	}	    

      }
      // wrong or invalid section
      // done with this line, but no action to take
      continue;
    }
	
    // not a section header
    // if we're not in the right section ignore it
    if (!insection)
      continue;

    // we're in the right section, process data
    // first special case: fs
    ret = regexec(&fs_pat, line, 3, match, 0);
    if (ret == 0) {
      char *value;

      value = line + match[1].rm_so;
      // terminate with nul
      line[match[1].rm_eo] = '\0';

      // if more than one first wins
      if (!fs) {
	fs = strdup(value);
      }
#ifdef DEBUG
      printf("fs %s\n", value);
#endif
      continue;
    }

    ret = regexec(&data_pat, line, 5, match, 0);
    // libzfs uses uint64_t. so even though zetabytes
    // are supposedly supported, you can't actually set
    // a quota bigger than about 10eb. The property is
    // stored as number of bytes. It is converted to
    // gb, etc, when printing, unless you ask for it
    // literally, in which case you get bytes.
    // we use the same parser that the zfs command does.
    // Note that it works in integer arithmeric unless there's
    // a decimal point, in which case it uses double and
    // then converts to 64-bit integer
    if (ret == 0) {
      char *attr;
      int isplus = 0;
      char *num;
      uint64_t amount;
      int i;

      attr = line + match[1].rm_so;
      // terminate with nul
      line[match[1].rm_eo] = '\0';

      // see if this is one of our groups
      // look up gid of the group in the file
      // our users normally have lots of groups
      // probably the quota spec won't have as many,
      // so it's better to do this lookup only
      // for the quota specs, rather than all
      // of the user's groups

      if (strcmp(attr, "default") != 0) {
	struct group grpstr;
	struct group *gr = &grpstr;
	// we have some big groups
	char buf[100000];
	if (getgrnam_r(attr, gr, buf, sizeof(buf), &gr) != 0) {
	  syslog(LOG_ERR, "grname failed group %s", attr);
	  continue;
	}
      
	// nonexistent group?
	if (!gr) {
	  syslog(LOG_ERR, "can't find group %s", attr);
	  continue;
	}

#ifdef DEBUG
	printf("checking %s %i\n", gr->gr_name, gr->gr_gid);
#endif
	// check against user's groups
	for (i = 0; i < ngroups; i++){
	  if (groups[i] == gr->gr_gid)
	    break;
	}

	// didn't find it, so ignore this line
	if (i == ngroups)
	  continue;
      }
      // group 'default' falls through and is always done

      if (line[match[2].rm_so] == '+')
	isplus = 1;

      num = line + match[3].rm_so;
      // terminate with nul
      line[match[3].rm_eo] = '\0';

      // parse 10.2GB, etc using ZFS's parser
      i = zfs_nicestrtonum(hdl, num, &amount);
      if (i != 0) {
	syslog(LOG_ERR, "%s isn't a valid quota", num);
	continue;
      }

      if (isplus) {
	incr += amount;
	if (incr < amount) {
	  syslog(LOG_ERR, "integer overflow computing quota");
	}
      } else if (amount > base)
	base = amount;

#ifdef DEBUG
      printf("attr %s plus >%d< num %s suffix %c amount %f\n", attr, isplus, num, unit, amount);
#endif
    } else {
      if (regexec(&skip_pat, line, 0, NULL, 0)) {
	syslog(LOG_ERR, "bad line in /etc/quotas.conf %s\n", line);
      }
      continue;
    }
  }
#ifdef DEBUG
  printf("base %lu incr %lu\n", base, incr);
#endif
  if (line)
    free(line);
  fclose(cf);

  uint64_t quotaval = base + incr;
  if (quotaval < base) {
    syslog(LOG_ERR, "integer overflow computing quota");
  }
  char *retquota = NULL;

  asprintf(&retquota, "%lu", quotaval);

  if (retquota && fs) {
    *fsret = fs;
    return retquota;
  } else {
    if (fs)
      free(fs);
    if (retquota)
      free(retquota);
    return(ERRQUOTA);
  }
}

#ifdef MAIN
int main(int argc, char *argv[]) {
  char * quota;
  char * fs = NULL;
  libzfs_handle_t *libh = libzfs_init();

  quota = getuserquota(libh, "/common/home/clh", "clh", &fs);
  printf("%s %s\n", quota, fs);
  free(quota);
}
#endif
