#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

struct addrmask {
  struct sockaddr addr;
  struct sockaddr mask;
};

int parse_addr_mask(char *spec, struct sockaddr *addr, struct sockaddr *mask) {
  char *cp;
  int i;
  int family;
  struct addrinfo *addrs;
  struct addrinfo hints;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;
  char buf[1024];

  cp = strchr(spec, '/');
  if (cp)
    *cp = '\0';
  i = getaddrinfo(spec, NULL, &hints, &addrs);
  if (i || !addrs->ai_canonname) {
    printf("hostname %s not found", spec);
    return 1;
  }
  
  if (addrs->ai_family == AF_INET) {
    memcpy(addr, addrs->ai_addr, sizeof(struct sockaddr_in));
  } else if (addrs->ai_family == AF_INET6) {
    memcpy(addr, addrs->ai_addr, sizeof(struct sockaddr_in6));
  } else {
    printf("illegal address type");
    freeaddrinfo(addrs);
    return 1;
  }

  // save so we can free the struct;
  family = addrs->ai_family;

  freeaddrinfo(addrs);

  if (cp)
    // skip /
    cp++;
  else if (family == AF_INET)
    cp = "32";
  else
    cp = "128";
    
  if (strspn(cp, "0123456789") == strlen(cp)) {
      int masklen = atoi(cp);
      // it's cidr

      if (family == AF_INET) {
	struct sockaddr_in *sin = (struct sockaddr_in *)mask;
	uint32_t m = 0;

	memset(sin, 0, sizeof(struct sockaddr_in));
	sin->sin_family = AF_INET;
	for(i = 0; i < masklen; i++)
	  m = (m >> 1) | 0x80000000;
	sin->sin_addr.s_addr = htonl(m);

      } else if (family == AF_INET6) {
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *)mask;
	uint32_t m = 0;
	int octets;
	int bits;
	uint8_t *bytes = sin->sin6_addr.s6_addr;

	memset(sin, 0, sizeof(struct sockaddr_in6));
	sin->sin6_family = AF_INET6;

	if (masklen > 128)
	  masklen = 128;
	// 8 : 1, 0, 9: 1,1, 1: 0,1
	octets = masklen / 8;
	bits = masklen % 8;
	
	if (octets > 0)
	  memset(bytes, 255, (size_t)octets);
	if (bits > 0) {
	  for(i = 0; i < bits; i++)
	    m = (m >> 1) | 0x80;
	  bytes[octets] = m;
	}
      }
  } else {
    // mask is an actual address
    i = getaddrinfo(cp, NULL, &hints, &addrs);
    if (i || !addrs->ai_canonname) {
      printf("mask %s not found", cp);
      return 1;
    }
    if (family != addrs->ai_family) {
      printf("mask must be same address type as address: %s", cp);
      freeaddrinfo(addrs);
      return 1;
    }
    if (addrs->ai_family == AF_INET) {
      memcpy(mask, addrs->ai_addr, sizeof(struct sockaddr_in));
    } else if (addrs->ai_family == AF_INET6) {
      memcpy(mask, addrs->ai_addr, sizeof(struct sockaddr_in6));
    }
    freeaddrinfo(addrs);
  }
}

int comparewithmask(struct sockaddr *a1, struct sockaddr *a2, struct sockaddr *mask) {
    // easy if types match
  printf("%d %d %d\n" , a1->sa_family, a2->sa_family, mask->sa_family);
    if (a1->sa_family == AF_INET && a2->sa_family == AF_INET) {
        struct sockaddr_in *aa1 = (struct sockaddr_in *)a1;
        struct sockaddr_in *aa2 = (struct sockaddr_in *)a2;
	struct sockaddr_in *aam = (struct sockaddr_in *)mask;
	printf("%x %x %x\n", aa1->sin_addr.s_addr, aa2->sin_addr.s_addr, aam->sin_addr.s_addr);
        return (aa1->sin_addr.s_addr & aam->sin_addr.s_addr) ==
	  (aa2->sin_addr.s_addr & aam->sin_addr.s_addr);
    }
    if (a1->sa_family == AF_INET6 && a2->sa_family == AF_INET6) {
	int i;
	
	uint8_t *bytes1 = ((struct sockaddr_in6 *)a1)->sin6_addr.s6_addr;
	uint8_t *bytes2 = ((struct sockaddr_in6 *)a2)->sin6_addr.s6_addr;
	uint8_t *bytesm = ((struct sockaddr_in6 *)mask)->sin6_addr.s6_addr;
	for (i = 0; i < 16; i++) {
	  if ((bytes1[i] & bytesm[i]) != (bytes2[i] & bytesm[i]))
	    return 0;
	}
	return 1;
    }
    // we only support a1 V6 and a2 V4. The only way different types
    // can work is if the V6 is IP4 in V6. In that case we only support
    // V4 net/mask.
    if (a1->sa_family == AF_INET && a2->sa_family == AF_INET6)
      return 0;

    // now a1 is 6 and a2/mask is 4. convert a1 to IPV4 if possible
    {
        struct sockaddr_in6 *aa1 = (struct sockaddr_in6 *)a1;
        struct sockaddr_in *aa2 = (struct sockaddr_in *)a2;
	struct sockaddr_in *aamask = (struct sockaddr_in *)mask;
        // prefix for v4 in v6
        unsigned char v4[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
        unsigned long addr = 0;
        int i;
	uint32_t m = 0;
	
	printf("mixed\n");
        // if it's not v4 in v6, can't possibly match a v4 address
        for (i = 0; i < 16; i++)
	  printf("%x ", aa1->sin6_addr.s6_addr[i]);
	printf("\n");
        for (i = 0; i < 12; i++) {
            if (aa1->sin6_addr.s6_addr[i] != v4[i])
                return 0;
	}
	printf("ok\n");
        // it is, convert last 4 bytes to a long
        for (i = 12; i < 16; i++)
            addr = (addr << 8) | aa1->sin6_addr.s6_addr[i];
	m = ntohl(aamask->sin_addr.s_addr);
        // now compare
	printf("%x %x %x\n", addr, m, ntohl(aa2->sin_addr.s_addr));
        return (addr & m)  == (ntohl(aa2->sin_addr.s_addr) & m);
    }
    return 0;
}


int main (int argc, char **argv) {
  struct sockaddr_storage addr;
  struct sockaddr_storage mask;
  void *sockaddr;
  char buf[1024];
  struct addrinfo *addrs;
  struct addrinfo hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;

  parse_addr_mask(argv[1], (struct sockaddr *)&addr, (struct sockaddr *)&mask);
  if (addr.ss_family == AF_INET) {
    sockaddr = &((struct sockaddr_in *)&addr)->sin_addr;
  } else if (addr.ss_family == AF_INET6) {
    sockaddr = &((struct sockaddr_in6 *)&addr)->sin6_addr;
  } else
    sockaddr = NULL;

  printf("final %s\n", inet_ntop(addr.ss_family, sockaddr, buf, sizeof(buf)-1));

  if (mask.ss_family == AF_INET) {
    sockaddr = &((struct sockaddr_in *)&mask)->sin_addr;
  } else if (mask.ss_family == AF_INET6) {
    sockaddr = &((struct sockaddr_in6 *)&mask)->sin6_addr;
  } else
    sockaddr = NULL;

  printf("mask %s\n", inet_ntop(mask.ss_family, sockaddr, buf, sizeof(buf)-1));

  getaddrinfo(argv[2], NULL, &hints, &addrs);
  printf("%d\n", comparewithmask((struct sockaddr *)addrs->ai_addr, (struct sockaddr *)&addr, (struct sockaddr *)&mask));

}

