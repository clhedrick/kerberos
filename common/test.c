#define _GNU_SOURCE   
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "ccacheutil.h"

void test_convert(char *in, char *out, uid_t uid) {
  char *new = convert_to_collection(in, uid);
  if (strcmp(new, out) != 0)
    printf("failure convert_to_collection %s %s %d -> %s\n", in, out, uid, new);
  free(new);
}

void test_to_uid(char *ptr, uid_t uid, uid_t right) {
  uid_t new = ccname_to_uid(ptr, uid);
  if (new != right)
    printf("failure to_uid %s %d %d %d\n", ptr, uid, right, new);
}

void test_is_type(char *ccname, int right) {
  int new = is_collection_type(ccname);
  if (new != right)
    printf("failure is_type %s %d %d\n", ccname, right, new);
}

void test_is_coll(char *ccname, int right) {
  int new = is_collection(ccname);
  if (new != right)
    printf("failure is_coll %s %d %d\n", ccname, right, new);
}


void test_get_type(char *ccname, char *type) {
  char *new = get_cc_type(ccname);
  if (strcmp(new, type) != 0) 
    printf("failure get_type %s %s %s\n", ccname, type, new);
}


int main (int argc, char **argv) {
  
  test_convert("/tmp/foo", "FILE:/tmp/foo", 0);
  test_convert("FILE:/tmp/foo", "FILE:/tmp/foo", 0);
  test_convert("DIR:/tmp/foo", "DIR:/tmp/foo", 0);
  test_convert("DIR::/tmp/foo//bar", "DIR:/tmp/foo", 0);
  test_convert("KEYRING:persistent:1003:xxx", "KEYRING:persistent:1003", 0);
  test_convert("KEYRING:persistent:1003", "KEYRING:persistent:1003", 0);
  test_convert("KCM:1003:xxx", "KCM:1003", 123);
  test_convert("KCM:1003", "KCM:1003", 123);
  test_convert("KCM:", "KCM:123", 123);
  test_convert("KCM:", "KCM:", (uid_t)-1);
  test_convert("KCM:1003", "KCM:", (uid_t)-1);
  test_convert("KCM:1003", "KCM:1003", 0);
  test_convert("foo", "foo", 0);

  test_to_uid("/home/hedrick", 0, 1003);
  test_to_uid("FILE:/home/hedrick", 0, 1003);
  test_to_uid("DIR:/home/hedrick/.ssh", 0, 1003);
  test_to_uid("DIR::/home/hedrick/.ssh", 0, 1003);
  test_to_uid("KEYRING:persistent:1003:xxx", 0, 1003);
  test_to_uid("KEYRING:persistent:1003", 0, 1003);
  test_to_uid("KCM:1003:xxx", 0, 1003);
  test_to_uid("KCM:1003", 0, 1003);
  test_to_uid("KCM:", 123, 123);
  test_to_uid ("foo", 0, (uid_t) -1);

  test_is_type("/home/hedrick", 0);
  test_is_type("FILE:/home/hedrick", 0);
  test_is_type("DIR:/home/hedrick/.ssh", 1);
  test_is_type("DIR::/home/hedrick/.ssh", 1);
  test_is_type("KEYRING:persistent:1003:xxx", 1);
  test_is_type("KEYRING:persistent:1003", 1);
  test_is_type("KCM:1003:xxx", 1);
  test_is_type("KCM:1003", 1);
  test_is_type("KCM:", 1);
  test_is_type ("foo", 0);

  test_is_coll("/home/hedrick", 0);
  test_is_coll("FILE:/home/hedrick", 0);
  test_is_coll("DIR:/home/hedrick/.ssh", 1);
  test_is_coll("DIR::/home/hedrick/.ssh", 0);
  test_is_coll("KEYRING:persistent:1003:xxx", 0);
  test_is_coll("KEYRING:persistent:1003", 1);
  test_is_coll("KCM:1003:xxx", 0);
  test_is_coll("KCM:1003", 0);
  test_is_coll("KCM:", 1);
  test_is_coll ("foo", 0);

  test_get_type("/home/hedrick", "FILE");
  test_get_type("FILE:/home/hedrick", "FILE");
  test_get_type("DIR:/home/hedrick/.ssh", "DIR");
  test_get_type("DIR::/home/hedrick/.ssh", "DIR");
  test_get_type("KEYRING:persistent:1003:xxx", "KEYRING");
  test_get_type("KEYRING:persistent:1003", "KEYRING");
  test_get_type("KCM:1003:xxx", "KCM");
  test_get_type("KCM:1003", "KCM");
  test_get_type("KCM:", "KCM");
  test_get_type ("foo", "unknown");


  printf("ok\n");
}
