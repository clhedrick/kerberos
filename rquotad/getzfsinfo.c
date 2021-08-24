#define _GNU_SOURCE 
#include <sys/nvpair.h>
#include <libnvpair.h>
#include <libzfs.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <string.h>
#include <regex.h>

struct zfsinfo {
 unsigned long ihardlimit;
 unsigned long isoftlimit;
 unsigned long curinodes;
 unsigned long bhardlimit;
 unsigned long bsoftlimit;
 unsigned long curspace;
};

int getzfsinfo (char *dirname, uid_t uid, struct zfsinfo *zp) {
  char propbuf[1024];
  char *attr = NULL;
  unsigned long quota;
  FILE *cf = NULL;
  char *line = NULL;
  size_t len = 0;
  char * filesys = NULL;
  char *type = NULL;
  int ret = -1;
  int havequotas = 0;
  regex_t fs_pat;
  int fs_compiled = 0;
  libzfs_handle_t *libh = NULL;
  zfs_handle_t *zh = NULL;
  struct passwd passwd;
  struct passwd *pwd = &passwd;
  struct passwd *rpwd = NULL;
  char pwdbuf[1024];
  
  // first find the ZFS file system
  cf = fopen("/proc/mounts", "r");
  if (!cf) {
    fprintf(stderr, "failed to open /etc/mounts\n");
    goto out;
  }

  while (getline(&line, &len, cf) != -1) {
    char *mountpoint;
    char *fsname;
    char *cp = line;


    if (!*cp)
      continue;  // invalid line
    fsname = cp;
    while (*cp && *cp != ' ')
      cp++;

    if (!*cp)
      continue;  // invalid line
    *cp = '\0';
    cp++;

    mountpoint = cp;
    while (*cp && *cp != ' ')
      cp++;

    if (!*cp)
      continue;  // invalid line
    *cp = '\0';
    cp++;
    
    type = cp;
    while (*cp && *cp != ' ')
      cp++;

    if (!*cp)
      continue;  // invalid line
    *cp = '\0';

    // found the right mount point?
    if (strcmp(dirname, mountpoint) == 0 && strcmp(type, "zfs") == 0) {
      // return file system
      filesys = strdup(fsname);
      break;
    }
  }

  if (!filesys) {
    fprintf(stderr, "mount point for %s not found\n", dirname);
    goto out;
  }
  
  // now have a zfs file system, filesys
  // see if it is in /etc/quotas.conf. Only report quotas if so
  if (regcomp(&fs_pat, "^[ \t]*:fs[ \t]*=[ \t]*([-a-zA-Z/0-9_+]+)[ \t]*$", REG_EXTENDED|REG_NEWLINE) != 0) {
    fprintf(stderr, "Can't compile fs_pat");
    goto out;
  }
  fs_compiled = 1;  // need to do regfree
  
  fclose(cf);
  cf = fopen("/etc/quotas.conf", "r");
  if (!cf) {
    fprintf(stderr, "unable to open /etc/quotas.conf");
    goto out;
  }
  
  while (getline(&line, &len, cf) != -1) {
    regmatch_t match[5];
    int ret;

    ret = regexec(&fs_pat, line, 2, match, 0);
    if (ret == 0) {
      char *value;

      // fs=name is the ZFS file system
      // save it in filesys
      value = line + match[1].rm_so;
      // terminate with nul
      line[match[1].rm_eo] = '\0';

      if (strcmp(value,filesys) == 0) {
	havequotas = 1;
	break;
      }
    }
  }

  if (!havequotas) {
    fprintf(stderr, "no quotas for %s\n", filesys);
    goto out;
  }

  if (getpwuid_r(uid, pwd, pwdbuf, sizeof(pwdbuf), &rpwd) != 0 ||
    ! rpwd) {
    fprintf(stderr, "can't find user %d\n", uid);
    goto out;
  }

  libh = libzfs_init();
  if (!libh) {
    fprintf(stderr, "can't open zfs library\n");
    goto out;
  }
  zh = zfs_open(libh, filesys, ZFS_TYPE_FILESYSTEM);
  if (!zh) {
    fprintf(stderr, "can't open file systen %s\n", filesys);
    goto out;
  }

  asprintf(&attr, "userquota@%s", pwd->pw_name);
  if (!attr)
    goto out;
  if (zfs_prop_get_userquota(zh, attr, propbuf, sizeof(propbuf)-1, 1) == 0) {
    zp->bhardlimit = atol(propbuf) / 1024;
    zp->bsoftlimit = atol(propbuf) / 1024;
  } else {
    zp->bhardlimit = 0L;
    zp->bsoftlimit = 0L;
  }
  free(attr);
  attr = NULL;

  asprintf(&attr, "userused@%s", pwd->pw_name);
  if (!attr)
    goto out;
  if (zfs_prop_get_userquota(zh, attr, propbuf, sizeof(propbuf)-1, 1) == 0)
    zp->curspace = atol(propbuf);
  else
    zp->curspace = 0L;    
  free(attr);
  attr = NULL;

  asprintf(&attr, "userobjused@%s", pwd->pw_name);
  if (!attr)
    goto out;
  strcpy(propbuf, "0"); // in case no quota for this user
  if (zfs_prop_get_userquota(zh, attr, propbuf, sizeof(propbuf)-1, 1) == 0) 
    zp->curinodes = atol(propbuf);
  else
    zp->curinodes = 0L;
  free(attr);
  attr = NULL;

  asprintf(&attr, "userobjquota@%s", pwd->pw_name);
  if (!attr)
    goto out;
  strcpy(propbuf, "0"); // in case no quota for this user
  if (zfs_prop_get_userquota(zh, attr, propbuf, sizeof(propbuf)-1, 1) == 0) {
    if (strcmp(propbuf, "none") == 0) {
      zp->ihardlimit = 0;
      zp->isoftlimit = 0;
    } else {
      zp->ihardlimit = atol(propbuf) / 1024;
      zp->isoftlimit = atol(propbuf) / 1024;
    }
  } else {
    zp->ihardlimit = 0;
    zp->isoftlimit = 0;
  }
  ret = 0;

out:
  if (attr)
    free(attr);
  if (cf)
    fclose(cf);
  if (line)
    free(line);
  if (filesys)
    free(filesys);
  if (fs_compiled)
    regfree(&fs_pat);
  if (zh)
    zfs_close(zh);
  if (libh)
    libzfs_fini(libh);
  return ret;
}

#ifdef MAIN
int main(int argc, char **args) {
  struct zfsinfo zfsinfo;
  int i;

  i = getzfsinfo (args[1], atoi(args[2]), &zfsinfo);
  if (i == 0) {
    printf("%lu %lu %lu %lu %lu %lu\n", zfsinfo.ihardlimit,
	zfsinfo.isoftlimit,
	zfsinfo.curinodes,
	zfsinfo.bhardlimit,
	zfsinfo.bsoftlimit,
	zfsinfo.curspace);
  } else {
    printf("error\n");
  }
}
#endif

    
	
