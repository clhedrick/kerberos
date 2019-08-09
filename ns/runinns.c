#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sched.h>
#include <sys/stat.h>

int main(int argc, char **argv) {
  pid_t parent = getpid();
  uid_t uid = getuid();
  uid_t gid = getgid();
  char * cmd;
  char * linkname;
  struct stat statbuf;
  int netns;
  int ret;
  char linkbuf[512];
  char *uidarg;
  char **oldenviron;
  
  // we want a clear environment for call to create.py, since
  // it's running as root. But when we call the user's program
  // we want him to see his normal environ
  oldenviron = environ;
  environ = NULL;

  // we're setuid. normalize environment
  setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin", 1);

  if (asprintf(&uidarg, "%d", uid) < 0) {
    printf("Can't allocate memory\n");
    exit(1);
  }

  if (asprintf(&linkname, "/var/run/user/%d/netnamespace", uid) < 0) {
    printf("Can't allocate memory\n");
    exit(1);
  }

  // supposedly stat follows links, so
  // we'll get a failure either if th link doesn't
  // exist or the file it points to doesn't
  ret = stat(linkname, &statbuf);
  // we need to check the link owner. if it's root, we
  // put it there. We don't want a user to be able to
  // create a link to another user's namespace.
  if (ret == 0) {
    // shouldn't be able to fail since stat worked
    ret = lstat(linkname, &statbuf);    
    // if owner not root, set failure so we'll kill link
    if (ret == 0 && statbuf.st_uid != 0)
      ret = 1;
  }

  if (ret != 0) {
    // in case link exists but file doesn't
    // or wrong user owns it
    // we want to remove the link and recreate it
    unlink(linkname);
  }

  // if link doesn't exist, call create.py to create it
  //   do a fork/exec rather than calling system, because
  // system may not work right for setuid
  if (ret != 0) {
    pid_t pid = fork();
    int status;
    if (pid > 0) {
      waitpid(pid, &status, 0);
    } else if (pid < 0) {
      printf("Forked failed\n");
      exit(1);
    } else {
      // might as well be root for real
      setresuid(0, 0, 0);
      execl("/usr/libexec/create.py", "create.py", uidarg, NULL);
      printf("Can't run /usr/libexec/create.py\n");
      exit(1);
    }
    // here after waitpid
    if (status != 0) {
      printf("Unable to create network name space top\n");
      exit(WEXITSTATUS(status));
    }

    if (stat(linkname, &statbuf) != 0) {
      printf("Couldn't find %s after it was supposed to be created\n", linkname);
      exit(1);
    }
  }

  free(cmd);

  //    snprintf(net_path, sizeof(net_path), "%s/%s", NETNS_RUN_DIR, name);
  netns = open(linkname, O_RDONLY | O_CLOEXEC);
  if (netns < 0) {
    fprintf(stderr, "Cannot open network namespace \"%s\": %s\n",
	    linkname, strerror(errno));
    exit(1);
  }

  if (setns(netns, CLONE_NEWNET) < 0) {
    fprintf(stderr, "setting the network namespace \"%s\" failed: %s\n",
	    linkname, strerror(errno));
    close(netns);
    return -1;
  }
  
  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);
  
  clearenv();
  environ = oldenviron;

  setenv("LD_LIBRARY_PATH", "/opt/ros/melodic/lib", 1);

  // free any existing environment, since we allocated some
  
  execvp(argv[1], &argv[1]);
  printf("execv failed\n");
  _exit(EXIT_FAILURE);   // exec never returns
}

