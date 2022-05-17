#include <stdio.h>


char *pam_getenv(void *pamh, char *varname) {
  return "/tmp/krb5test";
}

int pam_get_user(void *pamh, char **username, void *foo) {
  *username = "hedrick";
  return 0;
}

int pam_syslog(void *pamh, int level, char *str, long arg) {
  printf(str, arg);
  return 0;
}

int pam_putenv(void *pamh, char *str) {
  printf(str);
  return 0;
}

int main (int argc, char** argv) {
  pam_sm_open_session(NULL, 0, 0, NULL);
}


  
