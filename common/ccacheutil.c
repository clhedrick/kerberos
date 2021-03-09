/*
 * Copyright 2017 by Rutgers, the State University of New Jersey
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Rutgers not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original Rutgers software.
 * Rutgers makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

/*
 * all dependency upon specific cache types should be in this library
 * Note that this only handles types that are present on Linux. That
 * should be OK for Macs also, but Windows has 2 more types.
 */

#define _GNU_SOURCE   
#include <stdio.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

#define KEYRING_PREFIX "KEYRING:persistent:"

// If ptr is the name of a specific cache, and it's a collection type,
// convert it to the collection name. Always returns a malloced pointer,
// so caller must free it.
//
// KCM: presents a problem. The collection name is just KCM:. This is
// ambiguous. You have to setuid to the user's uid in order to look
// up the collection. Some of the code in renewd needs unambigous names.
// So if the collection name would be KCM, and a UID is passwd, return
// KCM:uid. To get just KCM:, pass (uid_t)-1.

char *
convert_to_collection(const char *ptr, uid_t uid) {
  char * retval;

  __asm__ (".symver memcpy,memcpy@GLIBC_2.2.5");

  if (strncmp(ptr, "KEYRING:", 8) == 0) {
    // count colons in ccname
    int numcolon = 0; 
    char *cp;

    retval = malloc(strlen(ptr) + 1);
    strcpy(retval, ptr);
    
    for (cp = retval; *cp; cp++) {
      if (*cp == ':')
	numcolon++;
      if (numcolon == 3) {
	*cp = '\0';
	break;
      }
    }
  } else if (strncmp(ptr, "DIR::", 5) == 0) {
    // collection ends at last /, but also remove any
    // redundant ones
    char *cp;

    retval = malloc(strlen(ptr) + 1);
    strcpy(retval, ptr);

    cp = strrchr(retval, '/');
    while (*(cp-1) == '/')
      cp--;
    *cp = '\0';
    memmove(retval + 4, retval + 5, cp - (retval+5) + 1);  // +1 because we need to copy the null
  } else if (strncmp(ptr, "KCM:", 4) == 0 && uid == (uid_t)-1) {
    asprintf(&retval, "KCM:");
  } else if (strcmp(ptr, "KCM:") == 0) {
    asprintf(&retval, "KCM:%lu", (unsigned long)uid);    
  } else if (strncmp(ptr, "KCM:", 4) == 0) {
    // since we have at least KCM: already there, there has to
    // be enough space for this strcpy
    // count colons in ccname
    int numcolon = 0; 
    char *cp;

    retval = malloc(strlen(ptr) + 1);
    strcpy(retval, ptr);

    for (cp = retval; *cp; cp++) {
      if (*cp == ':')
	numcolon++;
      if (numcolon == 2) {
	*cp = '\0';
	break;
      }
    }
  } else if (ptr[0] == '/') {
    asprintf(&retval, "FILE:%s", ptr);
  } else {
    retval = malloc(strlen(ptr) + 1);
    strcpy(retval, ptr);
  }
  return retval;
}

// get the UID from the ccname. E.g. KEYRING:persistent:uid
// returns uid. All the collection types have the name
// encoded, except "KCM:". For file and dir, UID isn't
// encoded, but we can look up the owner of the file.

// uid arg is used for KCM:. If ccname is a full cache name,
// it's KCM:uid..., so normal processing works, but KCM:
// alone is ambiguous.
uid_t
ccname_to_uid(const char *ptr, uid_t uid) {

  if (strncmp(ptr, "FILE:", strlen("FILE:")) == 0 ||
      strncmp(ptr, "DIR:", strlen("DIR:")) == 0 ||
      ptr[0] == '/') {
    // it's a file, use the owner
    struct stat statbuf;
    const char *path = ptr;

    if (strncmp(ptr, "FILE:", strlen("FILE:")) == 0)
      path += strlen("FILE:");
    else if (strncmp(ptr, "DIR::", strlen("DIR::")) == 0)
      path += strlen("DIR::");
    else if (strncmp(ptr, "DIR:", strlen("DIR:")) == 0)
      path += strlen("DIR:");

    if (stat(path, &statbuf) == 0)
      return statbuf.st_uid;
    else
      return -1;

  } else  if (strncmp(ptr, KEYRING_PREFIX, strlen(KEYRING_PREFIX)) == 0) {
    return atol(ptr + strlen(KEYRING_PREFIX));
  } else if (strncmp(ptr, "KCM:", 4) == 0) {
    // if it's just KCM, it means the current user, so there's nothing to check
    if (ptr[4] != '\0')
      return atol(ptr + strlen("KCM:"));
    else
      return uid;
  } else
    return -1;
}

// true if it's a collection type, even if ccname is actually a specific cache
// note that we're checking KEYRING:persistent:, not just KEYRING, because our
// code currently doesn't support the other keyring types
// we also don't support MEMORY, so we claim it's not a collection type
int
is_collection_type(const char *ccname) {
  return strncasecmp(ccname, KEYRING_PREFIX, strlen(KEYRING_PREFIX)) == 0 ||
    strncasecmp(ccname, "KCM:", strlen("KCM:")) == 0 ||
    strncasecmp(ccname, "DIR:", strlen("DIR:")) == 0;
}

// ccname is an actual collection
int
is_collection(const char *ccname) {
  if (strncasecmp(ccname, KEYRING_PREFIX, strlen(KEYRING_PREFIX)) == 0) {
    // count colons in ccname
    int numcolon = 0; 
    const char *cp;

    for (cp = ccname; *cp; cp++) {
      if (*cp == ':')
	numcolon++;
      if (numcolon == 3)
	return 0;
    }
    return 1;
  }
  // KCM: is officially a collection, but we can't use it
  // because it doesn't have the UID
  return (strcmp(ccname, "KCM:") == 0 && strlen(ccname) > 4) ||
    (strncmp(ccname, "DIR:", 4) == 0 && ccname[4] != ':');

}

// get type name from ccname.
// This code is a bit longer than you'd expect because I'm
// trying to avoid mallocing anything or hacking on the
// argument. This had better be a complete list of types.
char *
get_cc_type(const char *ccname) {
  if (strncasecmp(ccname, "KEYRING:", strlen("KEYRING:")) == 0)
    return "KEYRING";
  if (strncasecmp(ccname, "KCM:", strlen("KCM:")) == 0)
    return "KCM";
  if (strncasecmp(ccname, "DIR:", strlen("DIR:")) == 0)
    return "DIR";
  if (strncasecmp(ccname, "FILE:", strlen("FILE:")) == 0 || ccname[0] == '/')
    return "FILE";
  if (strncasecmp(ccname, "MEMORY:", strlen("MEMORY:")) == 0)
    return "MEMORY";
  return "unknown";
}
