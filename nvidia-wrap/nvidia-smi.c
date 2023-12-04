#define _GNU_SOURCE

#include <wait.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[], char *env[])
{
  char *slurm = getenv("SLURM_JOB_UID");
  uid_t uid = getuid();

  // if under slurm or we're root, pass all args and run as real user
  if (slurm || uid == 0) {
    printf("not setuid\n");
    setreuid(uid, uid);
    execve("/usr/bin/nvidia-smi", argv, env);

  // normal user, not slurm. setuid but with no args. This is the only
  // way users will be able to see what is going on, since they have
  // no access to the GPUs except in slurm
  } else {
  // create null argv and envp, for safety
    char **newargv = malloc(sizeof(char *) * 2);
    newargv[0] = "/usr/bin/nvidia-smi";
    newargv[1] = NULL;
    char **newenvp = malloc(sizeof(char *) * 1);
    newenvp[0] = NULL;

  // if normal user not under slurm, allow access but run without args
  // value = pid as string
    pid_t pid = getpid();
    char *value = NULL;
    asprintf(&value, "%u\n", pid);
    
  // write pid into this file to put pid in a cgroup with no restrictions
    // cgroups 1
    char *cfile = "/sys/fs/cgroup/devices/system.slice/tasks";
    // cgroups 2
    char *cfile2 = "/sys/fs/cgroup/cgroup.procs";

  // open file and write pid to it
    FILE *fd = fopen(cfile, "w");
    if (!fd) {
      fd = fopen(cfile2, "w");
    }
    if (!fd) {
      printf("Unable to open cgroups file\n");
      exit(1);
    }
    fputs(value, fd);
    fclose(fd);

  // change to user and run nvidia-smi with no args
    setreuid(uid, uid);
    execve("/usr/bin/nvidia-smi", newargv, newenvp);
  }
}

  
