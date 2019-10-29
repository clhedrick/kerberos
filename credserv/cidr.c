#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// WARNING: modifies its arg,
// so call ip2mask first

unsigned int ip2ui(char *ip);

unsigned int ip2ui(char *ip) {

  /* An IP consists of four ranges. */
  unsigned long ipAsUInt = 0;
  char *saveptr;
  char *cp;
	
  /* Deal with first range. */
  cp = strtok_r(ip, ".", &saveptr);
  while (cp) {
    ipAsUInt = (ipAsUInt << 8) | atoi(cp);
    cp = strtok_r(NULL, ".\0", &saveptr);
  }

  return (unsigned int)ipAsUInt;
}

unsigned int ip2mask(char *ip);

unsigned int ip2mask(char *ip) {
  int i;
  unsigned int mask = 0;
  char *cp;
  int bits;

  cp = strchr(ip, '/');
  if (!cp)
    return 0xffffffff;

  bits = atoi(cp + 1);

  for(i = 0; i < bits; i++)
    mask = (mask >> 1) | 0x80000000;

  return mask;
}

#ifdef CIDRMAIN
int main (int argc, char **argv) {
  unsigned int x, y;
  x = ip2mask(argv[1]);
  y = ip2ui(argv[1]);
  printf("%x %x\n", x, y);
}
#endif
