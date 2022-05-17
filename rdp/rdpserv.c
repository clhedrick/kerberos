/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/* 
 * This code is based on the Kerberos sample server, which contains the 
 * following license. There is, however, virtually none of the original 
 * code left here without rewriting.
 *
 * The current code is Copyright 2017, by Rutgers, the State University of
 * New Jersey. It is released under the same license as MIT's, with the obvious
 * replacement of MIT by Rutgers.
 */

/* 
 * Credserv, the service side of kgetcred/credserv. See the man page
 * for specifics of function.
 */

/*
 * Copyright 1990,1991 by the Massachusetts Institute of Technology.
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
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

#include "port-sockets.h"
#include "krb5.h"
#include "com_err.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wait.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <sys/stat.h>
#include <time.h>
#include <grp.h>
#include <signal.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#define SAMPLE_VERSION "KRB5_sample_protocol_v1.0"

int debug;

#define GENERIC_ERR "Unable to get credentials"
#define NOKEYTAB_ERR "You must register a keytable for this host before you can use this program."

static void
usage(char *name)
{
    fprintf(stderr, "usage: %s [-p port] [-s service] [-S keytab]\n",
            name);
}

void mylog (int level, const char *format, ...)  __attribute__ ((format (printf, 2, 3)));
void mylog (int level, const char *format, ...) {
    va_list args;
    va_start (args, format);

    if (debug) {
        vprintf(format, args);
        printf("\n");
    } else
        vsyslog(level, format, args);

    va_end(args);
}

// read specifid number of characters from a net connection
static int
net_read(int fd, char *buf, int len)
{
    int cc, len2 = 0;

    do {
        cc = SOCKET_READ((SOCKET)fd, buf, len);
        if (cc < 0) {
            if (SOCKET_ERRNO == SOCKET_EINTR)
                continue;

            /* XXX this interface sucks! */
            errno = SOCKET_ERRNO;

            return(cc);          /* errno is already set */
        }
        else if (cc == 0) {
            return(len2);
        } else {
            buf += cc;
            len2 += cc;
            len -= cc;
        }
    } while (len > 0);
    return(len2);
}

char *getcreds(krb5_context context, krb5_auth_context auth_context, char *username, char* uuid, char *myhostname, char *hostname, char *service, krb5_data *data, krb5_data *realm_data);

int krb5_net_write (krb5_context, int, const char *, int);

char * read_item(int sock, char *olditem);

// read an argument from the network connection. The client, kgetcred, sends arguments
// as a byte count and then binrary data.
//  olditem is to make sure we stop reading when there's an error
char * read_item(int sock, char *olditem) {
    int retval;
    short xmitlen;
    char *item;

    if (olditem == NULL)
        return NULL;

    // read count
    if ((retval = net_read(sock, (char *)&xmitlen,
                           sizeof(xmitlen))) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "net read failed--%s", error_message(errno));
        return NULL;
    }

    // read data
    xmitlen = ntohs(xmitlen);
    if (!(item = (char *)malloc((size_t) xmitlen + 1))) {
        mylog(LOG_ERR, "no memory while allocating buffer to read from client");
        return NULL;
    }
    if (xmitlen > 0) {
        if ((retval = net_read(sock, (char *)item,
                           xmitlen)) <= 0) {
            mylog(LOG_ERR, "connection abort while reading data from client");
            free(item);
            return NULL;
        }
    }
    item[xmitlen] = '\0';
    if (debug > 1)
        mylog(LOG_DEBUG, "parameter %s", item);
    return item;

}

void catch_alarm (int sig);

// called on timeout. The only reason for using this is to get logging
void catch_alarm (int sig)
{
    mylog(LOG_ERR, "timeout in credserv");
    exit(1);
}

/* 
   The sample was designed so it could be run directly or 
   called from inetd. I haven't tested the current code with
   inetd. It probably won't work.
*/

const char *ntoa(struct sockaddr *peername);
const char *ntoa(struct sockaddr *peername) {
    static char name[1024];
    int family = peername->sa_family;
    if (family == AF_INET) {
        return inet_ntop(AF_INET, &((struct sockaddr_in *)peername)->sin_addr, name, 1023);
    }
    if (family == AF_INET6) {
        // see if it's actually IPv4. that has ::ff:ff at the beginning
        struct sockaddr_in6 *aa2 = (struct sockaddr_in6 *)peername;
        // this is the v4 prefix
        unsigned char v4[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
        int i;

        // if it's not v4, just call inet_ntop
        for (i = 0; i < 12; i++)
            if (aa2->sin6_addr.s6_addr[i] != v4[i])
                return inet_ntop(AF_INET6, &((struct sockaddr_in6 *)peername)->sin6_addr, name, 1023);
        // v4, but can't call normal ntoa because it's an array not a struct
        snprintf(name, 1023, "%d.%d.%d.%d", 
                 aa2->sin6_addr.s6_addr[12],
                 aa2->sin6_addr.s6_addr[13],
                 aa2->sin6_addr.s6_addr[14],
                 aa2->sin6_addr.s6_addr[15]);
        return name;
    }
    return NULL;
}

int compare_addrs(struct sockaddr *a1, struct sockaddr *a2);
int compare_addrs(struct sockaddr *a1, struct sockaddr *a2) {
    // easy if types match
    if (a1->sa_family == AF_INET && a2->sa_family == AF_INET) {
        struct sockaddr_in *aa1 = (struct sockaddr_in *)a1;
        struct sockaddr_in *aa2 = (struct sockaddr_in *)a2;
        return aa1->sin_addr.s_addr == aa2->sin_addr.s_addr;
    }
    if (a1->sa_family == AF_INET6 && a2->sa_family == AF_INET6) {
        struct sockaddr_in6 *aa1 = (struct sockaddr_in6 *)a1;
        struct sockaddr_in6 *aa2 = (struct sockaddr_in6 *)a2;
        return memcmp(&(aa1->sin6_addr), &(aa2->sin6_addr), sizeof(struct in6_addr)) == 0;
    }
    // if one is v4 and other is v6, put the v6 in a2
    if (a1->sa_family == AF_INET6 && a2->sa_family == AF_INET) {
        struct sockaddr *temp = a2;
        a2 = a1;
        a1 = temp;
    }
    // now a1 is 4 and a2 is 6
    {
        struct sockaddr_in *aa1 = (struct sockaddr_in *)a1;
        struct sockaddr_in6 *aa2 = (struct sockaddr_in6 *)a2;
        // prefix for v4 in v6
        unsigned char v4[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
        unsigned long addr = 0;
        int i;

        // if it's not v4 in v6, can't possibly match a v4 address
        for (i = 0; i < 12; i++)
            if (aa2->sin6_addr.s6_addr[i] != v4[i])
                return 0;
        // it is, convert last 4 bytes to a long
        for (i = 12; i < 16; i++)
            addr = (addr << 8) | aa2->sin6_addr.s6_addr[i];
        // now compare
        return addr == ntohl(aa1->sin_addr.s_addr);
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    krb5_context context;
    krb5_auth_context auth_context = NULL;
    krb5_ticket * ticket;
    // sockaddr_storage is largest possible sockaddr, currently ipv6
    struct sockaddr_storage peername_storage;
    // most code wants a sockaddr; cast it once to avoid doing it all over the place
    struct sockaddr * peername = (struct sockaddr *)&peername_storage;
    struct addrinfo * addrs;
    struct addrinfo * addrsp;
    socklen_t namelen;
    int sock = -1;                      /* incoming connection fd */
    short xmitlen;
    krb5_error_code retval;
    krb5_principal server;
    char *cname;
    char *service = "host";
    short port = 756;             /* If user specifies port */
    extern int opterr, optind;
    extern char * optarg;
    int ch;
    krb5_keytab keytab = NULL;
    char *progname;
    int on = 1;
    char hostbuf[1024];
    char *myhostname = NULL;
    // args from kgetcred
    char *username;
    char *uuid;
    // end of args
    char *realhost;
    krb5_creds usercreds;
    krb5_data data;
    char *errmsg = GENERIC_ERR;
    int i;
    int found = 0;
    krb5_data realm_data;
    char *default_realm = NULL;
    struct addrinfo hints;


    // in case we're run by a user from the command line, get a known environment
    clearenv();

    memset(&usercreds, 0, sizeof(usercreds));
    memset(&hints, 0, sizeof(hints));
    // these are default arguments for addrinfo
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;

    progname = *argv;

    /* open a log connection */
    openlog("rdpserv", 0, LOG_DAEMON);

    /*
     * Parse command line arguments
     *
     */
    opterr = 0;
    while ((ch = getopt(argc, argv, "dp:S:s:")) != -1) {
        switch (ch) {
        case 'p':
            port = atoi(optarg);
            break;
        case 's':
            service = optarg;
            break;
        case 'd':
            debug++;
            break;
        case 'S':
            if ((retval = krb5_kt_resolve(context, optarg, &keytab))) {
                com_err(progname, retval,
                        "while resolving keytab file %s", optarg);
                exit(2);
            }
            break;

        case '?':
        default:
            usage(progname);
            exit(1);
            break;
        }
    }

    argc -= optind;
    argv += optind;

    // if not debug, detach
    if (!debug) {
        int fd;
        if (fork()) {
            // parent exits
            exit(0);
        }
        setsid(); // make process independent

        // close all descriptors
        for ( i=getdtablesize(); i>=0; --i) 
            close(i);
        
        // attach them to something known
        fd = open("/dev/null",O_RDWR, 0);
        
        if (fd != -1) {          
            dup2 (fd, STDIN_FILENO);
            dup2 (fd, STDOUT_FILENO);
            dup2 (fd, STDERR_FILENO);
            if (fd > 2)
                close (fd);
        }

    }

    if (chdir("/tmp") != 0) { // should be irrelevant. but just in case
        mylog(LOG_ERR, "chdir /tmp failed");
    }
        
    umask(027); // just to get something known, we shouldn't actually create any files

    /*
     * If user specified a port, then listen on that port; otherwise,
     * assume we've been started out of inetd.
     */

    if (port) {
        int acc;
        struct sockaddr_in6 sockin;
        memset(&sockin, 0, sizeof(sockin));

        if ((sock = socket(AF_INET6, SOCK_STREAM, 0)) < 0) {
            mylog(LOG_ERR, "socket: %m");
            exit(3);
        }
        /* Let the socket be reused right away */
        (void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                          sizeof(on));

        sockin.sin6_family = AF_INET6;
        sockin.sin6_port = htons(port);
        if (bind(sock, (struct sockaddr *) &sockin, sizeof(sockin))) {
            mylog(LOG_ERR, "bind: %m");
            exit(3);
        }
        if (listen(sock, 1) == -1) {
            mylog(LOG_ERR, "listen: %m");
            exit(3);
        }
        signal(SIGCHLD, SIG_IGN);
        if (debug) {
            namelen = sizeof(peername_storage);
            if ((acc = accept(sock, peername, &namelen)) == -1){
                mylog(LOG_ERR, "accept: %m");
                exit(3);
            }
        } else {
        while (1) {
            namelen = sizeof(peername_storage);
            if ((acc = accept(sock, peername, &namelen)) == -1){
                mylog(LOG_ERR, "accept: %m");
                exit(3);
            }
            if (fork()) {
                close(acc); // in parent
            } else {
                break;  // in child -- leave loop
            }
        }
        }
        // now in child
        dup2(acc, 0);
        close(sock);
        sock = 0;
    } else {
        /*
         * To verify authenticity, we need to know the address of the
         * client.
         */
        namelen = sizeof(peername_storage);
        if (getpeername(0, peername, &namelen) < 0) {
            mylog(LOG_DEBUG, "getpeername: %m");
            exit(1);
        }
        sock = 0;
    }

    // get our hostname, normalized
    // We're generating the local host principal needed for the forward call
    hostbuf[sizeof(hostbuf)-1] = '\0';
    gethostname(hostbuf, sizeof(hostbuf)-1);
    i = getaddrinfo(hostbuf, NULL, &hints, &addrs);
    if (i || !addrs->ai_canonname) {
        mylog(LOG_ERR, "hostname %s not found", hostbuf);
        goto cleanup;
    }
    myhostname = malloc(strlen(addrs->ai_canonname) + 1);
    strcpy(myhostname, addrs->ai_canonname);
    freeaddrinfo(addrs);

    retval = krb5_init_context(&context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
        exit(1);
    }

    // Mutual authentication, so we need credentials.
    // Ours comes from /etc/krb5.keytab

    if (keytab == NULL) {
        if ((retval = krb5_kt_resolve(context, "/etc/krb5.keytab", &keytab))) {
            com_err(progname, retval, "while resolving keytab file /etc/krb5.keytab");
            exit(2);
        }
    }

    if ((retval = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(retval));
        exit(1);
    }

    // Get options from /etc/krb5.conf

    realm_data.data = default_realm;
    realm_data.length = strlen(default_realm);

    // create a service principal for host/HOSTNAME
    retval = krb5_sname_to_principal(context, NULL, service,
                                     KRB5_NT_SRV_HST, &server);
    if (retval) {
        mylog(LOG_ERR, "while generating service name (%s): %s",
               service, error_message(retval));
        exit(1);
    }

    if (peername->sa_family != AF_INET && peername->sa_family != AF_INET6) {
        mylog(LOG_ERR, "request not IPv4 or 6 %d", peername->sa_family);
        exit(1);
    }

    mylog(LOG_DEBUG, "connection from %s", ntoa(peername));

    // I'm not sure why this is needed, but we've seen hung forks

    signal (SIGALRM, catch_alarm);
    alarm(60);  // a minute is more than enough

    // Get authenticated connection from client. 
    // Client's credentials are put into ticket and auth_context.  Ours comes from keytab
    // auth_context is used to encrypt the ticket we generate so communication with
    // the user is encrypted

    retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
                           SAMPLE_VERSION, server,
                           0,   /* no flags */
                           keytab,      /* default keytab is NULL */
                           &ticket);
    if (retval) {
        mylog(LOG_ERR, "recvauth failed 1--%s", error_message(retval));
        exit(1);
    }

    // Get argument. Currently just two: username and uuid

    // the rest of the arguments from the client
    username = read_item(sock, "");
    uuid = read_item(sock, username);

    // if any previous reads failed, the later ones reeturn null
    if (!uuid) {
        mylog(LOG_ERR, "missing arguments in kerberized request");
        goto cleanup;
    }

    mylog(LOG_DEBUG, "operation for user %s uuid %s from host %s", username, uuid, ntoa(peername));
    // Get client name (i.e. principal by which client authenticated ) from ticket.
    // This is typically the user running kgetcred, except that for the 'G' operation
    // it's the host principal from /etc/krb5.keytab on the client side.

    retval = krb5_unparse_name(context, ticket->enc_part2->client, &cname);
    if (retval){
        mylog(LOG_ERR, "unable make sense of client principal--%s", error_message(retval));
        goto cleanup;
    }

    if (strncmp("host/", cname, 5) != 0) {
        mylog(LOG_ERR, "request wasn't authenticated at host");
        goto cleanup;
    }
        
    // User is authenticated as a host. verify that the request came from that host
    // If a host has more than one name, this is more likely to produce the right answer
    // than a simple lookup. (For alternatives where we don't have the host
    // credentials, we just to a reverse lookup of the IP address it's coming from.

    char *hoststart;
    char *hostend;
    
    // cname is the principal the client was authenticated as. In this
    // case it's host/HOSTNAME@DOMAIN
    // Isolate the HOSTNAME part
    hostend = index(cname, '@');
    if (!hostend) {
        mylog(LOG_ERR, "principal missing @ %s", cname);
        goto cleanup;
    }
    hoststart = index(cname, '/');
    if (!hoststart) {
        mylog(LOG_ERR, "principal missing / %s", cname);
        goto cleanup;
    }
    *hostend = '\0';  // terminate, to give us separate service and host
    *hoststart = '\0';
    // Make sure it actually starts with host/
    if (strcmp("host", cname) != 0) {
        mylog(LOG_ERR, "request not from host %s", cname);
        goto cleanup;
    }
    // now handle the hostname. Forward lookup on the name,
    // then make sure the IP is on the list of addresses for
    // that name.
    i = getaddrinfo(hoststart+1, NULL, &hints, &addrs);
    if (i) {
        mylog(LOG_ERR, "can't find hostname %s", hoststart + 1);
        goto cleanup;
    }
    
    // make sure request is actually from this host
    for(addrsp = addrs; addrsp != NULL; addrsp = addrsp->ai_next) {
        // first entry is canon name
        if (addrsp == addrs)
            strncpy(hostbuf, addrsp->ai_canonname, sizeof(hostbuf) - 1);            
        if (compare_addrs(addrsp->ai_addr, peername)) {
            found = 1;
            break;
        }
    }
    if (!found) {
        mylog(LOG_ERR, "peer address %s doesn't match hostname %s",
              ntoa(peername), hoststart+1);
        goto cleanup;
    }
    *hostend = '@';  // put back punctuation so we have the whole principal again
    *hoststart = '/';
    // normalized name
    realhost = hostbuf;
    freeaddrinfo(addrs);

    errmsg = getcreds(context, auth_context, username, uuid, myhostname, realhost, service, &data, &realm_data);

    // return the results to the client
    // we return a one-byte code saying whether it's an error message, a listing, etc.
    if (errmsg == NULL) {
        char status[1];
        mylog(LOG_DEBUG, "returning data to client %s for user %s length %d", ntoa(peername), username, data.length);
        status[0] = 'c'; // for G we are returning credentials

        // write the one byte
        if ((retval = krb5_net_write(context, 0, (char *)status, 1)) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }

        // now write the actual data as a count then the data
        xmitlen = htons(data.length);
        if ((retval = krb5_net_write(context, 0, (char *)&xmitlen,
                                 sizeof(xmitlen))) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }
        if ((retval = krb5_net_write(context, 0, (char *)data.data,
                                     data.length)) < 0) {
            mylog(LOG_ERR, "%m: while writing data to client");
            exit(1);
        }
    } else {
        // error message. return the message
        char status[1];
        // the first byte is "e", meaning it's an error message
        status[0] = 'e'; // error message
        mylog(LOG_DEBUG, "returning error to client %s for user %s %s", ntoa(peername), username, errmsg);
        
        if ((retval = krb5_net_write(context, 0, (char *)status, 1)) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }

        // now write the message, as a byte count and then the text
        xmitlen = htons(strlen(errmsg));
        if ((retval = krb5_net_write(context, 0, (char *)&xmitlen,
                                 sizeof(xmitlen))) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }

        if ((retval = krb5_net_write(context, 0, errmsg, strlen(errmsg))) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }
    }

 cleanup:

    // no cleanup since we're forked

    exit(0);
}

/*
 * Finally the actual operations
 * Note that this code must check permissions
 * of the caller.
 */

// getcreds is called with host authentication.
// The host tells us who the user is
// We return a kerberos ticket, if the user has authorized that host to get a ticket

// returns NULL if OK, else error message
char *
getcreds(krb5_context context, krb5_auth_context auth_context, char *username, char *uuid, char *myhostname, char *hostname, char *service, krb5_data *data, krb5_data *realm_data) {
    krb5_error_code r;
    krb5_ccache ccache = NULL;
    krb5_ccache tempcache;
    krb5_creds creds;
    krb5_principal serverp = 0;
    char *default_realm = NULL;
    krb5_principal userprinc;
    char *prinname;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }

    if (asprintf(&prinname, "/var/spool/guacamole/krb5guac_%s_%s", username, uuid) < 0) {
        mylog(LOG_ERR, "asprintf failed user principal");
        return GENERIC_ERR;        
    }

    if ((r = krb5_cc_resolve(context, prinname, &ccache)) < 0) {
        mylog(LOG_ERR, "can't find user's cache");
        return GENERIC_ERR;        
    }

    // we now have credentials in ccache. 
        
    // we want to renew them, so the user has the full lifetime

    // we have to make a credentials cache to put the renewed credentials in

    if ((r = krb5_cc_new_unique(context, "MEMORY", "/tmp/jjjjj", &tempcache))) {
        mylog(LOG_ERR, "unable to make credentials file for host %s", error_message(r));
        return GENERIC_ERR;
    }

    if ((r = krb5_cc_get_principal(context, ccache, &userprinc)) < 0) {
        mylog(LOG_ERR, "could not get user principal from cached");
        return GENERIC_ERR;        
    }

    if ((r = krb5_cc_initialize(context, tempcache, userprinc))) {
        mylog(LOG_ERR, "unable to initialized temp credentials file for host %s", error_message(r));
        return GENERIC_ERR;
    }             

    if ((r = krb5_get_renewed_creds(context, &creds, userprinc, ccache, NULL))) {
        mylog(LOG_ERR, "unable to renew credentials %s", error_message(r));
        return GENERIC_ERR;
    }        

    if ((r = krb5_cc_store_cred(context, tempcache, &creds))) {
        mylog(LOG_ERR, "unable to store renewed credentials %s", error_message(r));
        return GENERIC_ERR;
    }        
    

    // for the forward, we need the local IP addresses in auth_content.
    /* fd is always 0 because the real one gets put onto 0 by dup2 */
    if ((r = krb5_auth_con_genaddrs(context, auth_context, 0,
                                    KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR)) < 0) {
        mylog(LOG_ERR, "could not get local full address %s",error_message(r));
        goto cleanup;
    }

   
    // Now we've got all the info to generate the forwarded credential.
    // This operation takes a credential appropriate for our system and
    // turns it into one appropriate for hostname.

    if ((r = krb5_fwd_tgt_creds(context, auth_context, hostname, userprinc, serverp,
			        tempcache, 1, data))) {
      mylog(LOG_ERR, "error getting forwarded credentials for user %s %s",username, error_message(r));
      goto cleanup;
    }

    // good return. The new, adjusted credential is in data. It's actually
    // a KRB-CRED message, which has the most sensitive part encrypted
    // in the session key. krb5_rd_cred in the client reads this message and
    // produces the actual credential.

    mylog(LOG_INFO, "credserv returning credentials for user %s to host %s", username, hostname);

    return 0;
    // since we forked, we're not actually doign cleanup
 cleanup:

    return GENERIC_ERR;

}
