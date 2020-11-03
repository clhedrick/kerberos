#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int zfs_nicestrtonum(char *hdl, char *num, unsigned long *squotaval) {
  char *cp = num;
  char save;
  unsigned long ret;
  double fret;

  // skip white space
  while (*cp == ' ' || *cp == '\t')
    cp++;

  if (*cp < '0' || *cp > '9')
    return 1;

  if (strchr(cp, '.')) {
    // have to use float 

    // get number part
    fret = strtod(cp, &cp);

    // skip white space
    while (*cp == ' ' || *cp == '\t')
      cp++;

    // if end of string, we're done
    if (!*cp) {
      *squotaval = (long)fret;
      return 0;
    }
    
    if (strchr("kKmMgGtT", *cp)) {
      fret *= 1024;
      if (strchr("mMgGtT", *cp)) 
	fret *= 1024;
      if (strchr("gGtT", *cp))
	fret *= 1024;
      if (strchr("tT", *cp))
	fret *= 1024;
      cp ++;
    }
    ret = (long)fret;
  } else {
    // integer

    // get number part
    ret = strtoul(cp, &cp, 10);

    // skip white space
    while (*cp == ' ' || *cp == '\t')
      cp++;

    // if end of string, we're done
    if (!*cp) {
      *squotaval = ret;
      return 0;
    }
    
    if (strchr("kKmMgGtT", *cp)) {
      ret *= 1024;
      if (strchr("mMgGtT", *cp)) 
	ret *= 1024;
      if (strchr("gGtT", *cp))
	ret *= 1024;
      if (strchr("tT", *cp))
	ret *= 1024;
      cp ++;
    }
  }

  // can end in B
  if (*cp && strchr("bB", *cp))
    cp++;
  
  // skip white space
  while (*cp == ' ' || *cp == '\t')
    cp++;

  // better be nothing else
  if (*cp)
    return 1;

  *squotaval = ret;
  return 0;
}

#ifdef MAIN
int main (int argc, char **argv) {
  unsigned long val;
  int ret = zfs_nicestrtonum(NULL, argv[1], &val);

  printf("%d %lu\n", ret, val);
}
#endif
