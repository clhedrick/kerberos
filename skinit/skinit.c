/*
  setuid root
  kinit -c "KEYRING:session:$MUID:$$" -t -k /etc/krb5.keytab
  as user: kinit $@
  kdestroy -c "KEYRING:session:$MUID:$$"
*/

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

char keyring[256];
int gstatus;
char **environ;

// destroy ticket and exit

void cleanup (int exitstatus) {

  pid_t pid = vfork();

  if (pid == -1) {
    fprintf(stderr, "fork failed\n");
    exit(1);
  } else if (pid > 0) {
    // parent
    int status;
    waitpid(pid, &status, 0);
    // ignore error return. we want to exit with the status of the main call
  } else {
    // kdestroy -c "KEYRING:session:$MUID:$$"
    // null environment, for safety
    execle("/bin/kdestroy", "kdestroy", "-c", keyring, NULL, environ);
    exit(1); // shouldn't happen
  }

  exit(exitstatus);
}

void intHandler(int dummy) {
  cleanup(gstatus);
}

main(int argc, char *argv[]) 
{
  char hostname[512];
  char hostprinc[512];
  char **newargv = malloc(sizeof(char *) * (argc + 3));

  environ = malloc(sizeof(char *));
  environ[0] = NULL;

  gstatus = 0;

  gethostname(hostname, sizeof(hostname) - 1);
  hostname[sizeof(hostname) - 1] = '\0';  // spec allows for no null termination, so make sure it's there
  snprintf(hostprinc, sizeof(hostprinc) - 1, "host/%s", hostname);
  hostprinc[sizeof(hostprinc) - 1] = '\0';

  pid_t parent = getpid();
  sprintf(keyring, "KEYRING:session:0:%u", parent);

  pid_t pid = vfork();

  if (pid == -1) {
    fprintf(stderr, "fork failed\n");
    exit(1);
  } else if (pid > 0) {
    // parent
    int status;
    waitpid(pid, &status, 0);
    if (status)
      exit(status);
  } else {
    // kinit -c "KEYRING:session:$MUID:$$" -t -k /etc/krb5.keytab
    // null environment, for safety
    // I'm supplying arguments to restrict the ticket as much as possible. Only last for 5 min, not forwarsable
    execle("/bin/kinit", "kinit", "-c", keyring, "-F", "-a", "-l", "5m", "-r", "5m", "-k", "-t", "/etc/krb5.keytab", hostprinc, NULL, environ);
    exit(1); // shouldn't happen
  }

  // have key, make sure we destroy it on exit
  signal(SIGINT, intHandler);

  pid = vfork();

  if (pid == -1) {
    fprintf(stderr, "fork failed\n");
    exit(1);
  } else if (pid > 0) {
    // parent
    waitpid(pid, &gstatus, 0);
    // note: we'll return gstatus, but
    // even if non-zero we continue, becauase we want to destroy the credentials
  } else {
    int i;

    // as user: kinit $@ with original environment variables
    // drop privs
    setregid(getgid(), getgid());
    setreuid(getuid(), getuid());
    newargv[0] = "kinit";
    newargv[1] = "-T";
    newargv[2] = keyring;
    for (i = 1; i < argc; i++) 
      newargv[2 + i] = argv[i];
    newargv[2 + i] = NULL;

    argv[0] = "kinit";
    execv("/bin/kinit", newargv);
    exit(1); // shouldn't happen
  }

  cleanup(gstatus);
}

