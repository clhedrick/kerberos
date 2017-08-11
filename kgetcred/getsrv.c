#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <stdlib.h>
#include <strings.h>
#include <arpa/inet.h>  // For solaris
#include <arpa/nameser.h>
#include <resolv.h>

#ifndef T_SRV
#define T_SRV		33
#endif

struct hostentry {
  char *name;
  unsigned short priority;
  unsigned short weight;
};

static int
cmphost(const void *p1, const void *p2)
{
  struct hostentry *h1 = (struct hostentry *)p1;
  struct hostentry *h2 = (struct hostentry *)p2;

  if (h1->priority < h2->priority)
    return -1;
  else if (h1->priority > h2->priority)
    return 1;
  else if (h1->weight > h2->weight)
    return -1;
  else if (h1->weight < h2->weight)
    return 1;
  else
    return 0;
}



char **getsrv( const char * domain,
			 const char * service, const char * protocol ) {
    char answer[1500]; // should be enough for at least 4 hosts
    int n;
    char *dname;
    int ancount, qdcount;		/* answer count and query count */
    HEADER *hp;			/* answer buffer header */
    struct hostentry *hostdata;
    char **hosts;
    int answerno;
    u_char hostbuf[256];
    u_char *msg, *eom, *cp;	/* answer buffer positions */
    int dlen, type, priority, weight, port;

    if ( !domain || !*domain ||
	 !service || !*service ||
	 !protocol || !*protocol )
	return NULL;

    asprintf(&dname, "_%s._%s.%s", service, protocol, domain);
        
    n = res_query(dname, C_IN, T_SRV, answer, sizeof(answer));

    (void) free(dname);

    if (n < (int)sizeof(HEADER) )
	return NULL;

    /* valid answer received. skip the query record. */

    hp = (HEADER *)answer;
    qdcount = ntohs(hp->qdcount);
    ancount = ntohs(hp->ancount);

    msg = (u_char *)answer;
    eom = (u_char *)answer + n;
    cp  = (u_char *)answer + sizeof(HEADER);

    while (qdcount-- > 0 && cp < eom) {
        n = dn_expand(msg, eom, cp, (char *)hostbuf, 256);
	if (n < 0)
	  return NULL;
	cp += n + QFIXEDSZ;
    }

    // answer will go here
    hostdata = malloc((ancount + 1) * sizeof(struct hostentry));
    answerno = 0;

    /* loop through the answer buffer and extract SRV records */
    while (ancount-- > 0 && cp < eom) {
        n = dn_expand(msg, eom, cp, (char *)hostbuf, 256);
	if (n < 0) {
	    // error, free malloced memory before returning
	    for(n = 0; n < answerno; n++)
	      free(hostdata[n].name);
	    (void)free(hostdata);
	    return NULL;
	}

	cp += n;

	// despite the name, getshort gets an unsigned short
	type = _getshort(cp);
	cp += sizeof(u_short);

	/* class = _getshort(cp); */
	cp += sizeof(u_short);

	/* ttl 4 bytes, int or long depending upon arch*/
	cp += 4;

	dlen = _getshort(cp);
	cp += sizeof(u_short);

	// not srv record, skip to the next record
	if ( type != T_SRV ) {
	    cp += dlen;
	    continue;
	}

	priority = _getshort(cp);
	cp += sizeof(u_short);
	hostdata[answerno].priority = priority;

	weight = _getshort(cp);
	cp += sizeof(u_short);
	hostdata[answerno].weight = weight;

	port = _getshort(cp);
	cp += sizeof(u_short);

	n = dn_expand( msg, eom, cp, (char *)hostbuf, 256 );
	if (n < 0)
	    break;
	cp += n;

	hostdata[answerno].name = malloc(strlen((char *)hostbuf) + 1);
	strcpy(hostdata[answerno].name, (char *)hostbuf );

	answerno++;
    }
    if (answerno) {
      int i;
      qsort(hostdata, answerno, sizeof(struct hostentry), cmphost);

      hosts = malloc((answerno + 1) * sizeof(char *));
      bzero(hosts, (answerno + 1) * sizeof(char *));
      for (i = 0; i < answerno; i++) {
	hosts[i] = hostdata[i].name;
      }
    }
    free(hostdata);
    if (answerno)
      return hosts;
    else
      return NULL;

}

/*
int main(int argc, char *argv[]) {
  int i;
  char **hosts = getsrv("CS.RUTGERS.EDU", "kerberos", "tcp");
  
  if (!hosts) {
    printf("none found \n");
    exit(0);
  }
  for (i = 0; hosts[i]; i++) {
    printf("%s\n", hosts[i]);
    free(hosts[i]);
  }
  free(hosts);
  
}
*/
