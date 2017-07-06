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
#include "credldap.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sample.h"

extern krb5_deltat krb5_clockskew;

extern int debug;

// credentaisl is a list of lists. 

struct hostlist {
    char *host;
    char *flags;
    struct hostlist *next;
};

struct princlist {
    char *principal;
    struct hostlist *hosts;
    struct princlist *next;
};

char *admingroup = NULL;


#ifndef GETPEERNAME_ARG3_TYPE
#define GETPEERNAME_ARG3_TYPE int
#endif

#define GENERIC_ERR "Unable to get credentials"
#define NOKEYTAB_ERR "You must register a keytable for this host before you can use this program."

static void
usage(char *name)
{
    fprintf(stderr, "usage: %s [-p port] [-s service] [-S keytab]\n",
            name);
}


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

int krb5_net_write (krb5_context, int, const char *, int);

char * read_item(int sock, char *olditem);

char * read_item(int sock, char *olditem) {
    int retval;
    short xmitlen;
    char *item;

    if (olditem == NULL)
        return NULL;

    if ((retval = net_read(sock, (char *)&xmitlen,
                           sizeof(xmitlen))) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        return NULL;
    }

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

int isprived(char *principal);

// if user is in group defined in admingroup
int isprived(char *principal) {
    char *cp;
    struct group *g;
    int i;

    if (!admingroup)
        return 0;

    // need a username, not a principal. stop at @
    cp = strchr(principal, '@');
    if (!cp)
        return 0;

    // get group
    g = getgrnam(admingroup);
    if (!g)
        return 0;

    *cp = '\0';  // stop at @; need to restore @ afterwards
    for (i = 0; g->gr_mem[i]; i++) {
        if (strcmp(principal, g->gr_mem[i]) == 0) {
            *cp = '@';            
            return 1;
        }
    }
    *cp = '@';            
    return 0;
}

// we want to make sure that the user got fresh credentials,
// so root can't use something lying around. 30 sec allows
// for some clock skew and processing time. Shorter might be
// better.

int isrecent(krb5_ticket *ticket);

int isrecent(krb5_ticket *ticket) {
    time_t now;

    krb5_ticket_times times;

    if (ticket->enc_part2 == NULL) {
        mylog(LOG_ERR, "decrypted ticket not available");
        return 1;
    }

    now = time(0);
    times = ticket->enc_part2->times;

    if ((now - times.authtime) > 30) {
        mylog(LOG_ERR, "ticket is too old");
        return 0;
    }

    return 1;

}

/* the actual operations */

char *getcreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *myhostname, char *hostname, char *service, krb5_data *data);
char *listcreds(krb5_context context, krb5_auth_context  auth_context, char * username, char *principal, char *myhostname, char *hostname, char *service,  krb5_data *data, char *cname);
char *registercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *myhostname, char *hostname, char *realhost, char *service, krb5_data *outdata, char *clientp, krb5_ticket *ticket, char * flags);
char *unregistercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *myhostname, char *hostname, char *realhost, char *service, krb5_data *outdata, char *clientp, krb5_ticket *ticket);

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
        char *retval;

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
        return retval;
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
    char repbuf[BUFSIZ];
    char *cname;
    char *service = "credserv";
    short port = 755;             /* If user specifies port */
    extern int opterr, optind;
    extern char * optarg;
    int ch;
    krb5_keytab keytab = NULL;
    char *progname;
    int on = 1;
    char hostbuf[1024];
    char *myhostname = NULL;
    // args from kgetcred
    char op; // operation: G - get creds, S - set creds; future delete and list
    char *username;
    char *principal;
    char *hostname;
    char *flags;
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
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;

    progname = *argv;

    retval = krb5_init_context(&context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
        exit(1);
    }

    /* open a log connection */
    openlog("credserv", 0, LOG_DAEMON);

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

    /* Backwards compatibility, allow port to be specified at end */
    if (argc > 1) {
        port = atoi(argv[1]);
    }

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

    chdir("/tmp"); // should be irrelevant. but just in case
    umask(027); // just to get something known, we shouldn't actually create any files

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

    // Mutual authentication, so we need credentials.
    // Ours comes from /etc/krb5.conf

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

    krb5_appdefault_string(context, "credserv", &realm_data, "admingroup", "", &admingroup);
    if (strlen(admingroup) == 0)
        admingroup = NULL;


    retval = krb5_sname_to_principal(context, NULL, service,
                                     KRB5_NT_SRV_HST, &server);
    if (retval) {
        mylog(LOG_ERR, "while generating service name (%s): %s",
               service, error_message(retval));
        exit(1);
    }

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


    if (peername->sa_family != AF_INET && peername->sa_family != AF_INET6) {
        mylog(LOG_ERR, "request not IPv4 or 6 %d", peername->sa_family);
        exit(1);
    }

    mylog(LOG_DEBUG, "connection from %s", ntoa(peername));

    // I'm not sure why this is needed, but we've seen hung forks

    signal (SIGALRM, catch_alarm);
    alarm(60);  // a minute is more than enough

    // get authenticated connection from client. Returns
    // client's credentials in ticket.  Our comes from keytab

    retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
                           SAMPLE_VERSION, server,
                           0,   /* no flags */
                           keytab,      /* default keytab is NULL */
                           &ticket);
    if (retval) {
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }

    // Get arguments from kgetcred: operation, username, principal, flags, and hostname
    // Not all operations use all three but it's easier to be uniform.

    // op
    if ((retval = net_read(sock, (char *)&op, 1)) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }

    username = read_item(sock, (char *)&op);
    principal = read_item(sock, (char *)username);
    flags = read_item(sock, (char *)principal);
    hostname = read_item(sock, (char *)flags);

    // if any previous reads failed, the later ones reeturn null
    if (!hostname)
        exit(1);

    mylog(LOG_DEBUG, "operation %c for user %s principal %s from host %s", op, username, principal, ntoa(peername));
    // Get client name (i.e. principal by which client authenticated ) from ticket.
    // This is typically the user running kgetcred, except that for the 'G' operation
    // it's the host principal from /etc/krb5.keytab on the client side.
    repbuf[sizeof(repbuf) - 1] = '\0';
    retval = krb5_unparse_name(context, ticket->enc_part2->client, &cname);
    if (retval){
        mylog(LOG_ERR, "unable make sense of client principal--%s", error_message(retval));
        goto cleanup;
    }

    if (op == 'G' || strncmp("host/", cname, 5) == 0)  {
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
                strncpy(hostbuf, addrsp->ai_canonname, sizeof(hostbuf));            
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
    } else {
        //all we have is an ip address. just do reverse lookup
        if (getnameinfo(peername, namelen, hostbuf, sizeof(hostbuf), NULL, 0, NI_NAMEREQD)) {
            mylog(LOG_ERR, "can't find hostname from IP %m");
            goto cleanup;
        }        
        realhost = hostbuf;
    }
    // end principal check

    // do the real operations
    if (op == 'G') 
        errmsg = getcreds(context, auth_context, username, principal, myhostname, realhost, service, &data);
    else if (op == 'L') 
        errmsg = listcreds(context, auth_context, username, principal, myhostname, realhost, service, &data, cname);
    else if (op == 'R') 
        errmsg = registercreds(context, auth_context, username, principal, myhostname, hostname, realhost, service, &data, cname, ticket, flags);
    else if (op == 'U') 
        errmsg = unregistercreds(context, auth_context, username, principal, myhostname, hostname, realhost, service, &data, cname, ticket);

    // return the results to the client
    if (errmsg == NULL) {
        char status[1];
        mylog(LOG_DEBUG, "returning data to client %s for user %s length %d", ntoa(peername), username, data.length);

        if (op == 'G')
            status[0] = 'c'; // credentials
        else
            status[0] = 'l'; // listing

        if ((retval = krb5_net_write(context, 0, (char *)status, 1)) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }

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
        status[0] = 'e'; // error message
        mylog(LOG_DEBUG, "returning error to client %s for user %s %s", ntoa(peername), username, errmsg);

        if ((retval = krb5_net_write(context, 0, (char *)status, 1)) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }

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
// We return the credentials they have registered for that host.

// returns NULL if OK, else error message
char *
getcreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *myhostname, char *hostname, char *service, krb5_data *data) {
    krb5_error_code r;
    krb5_ccache ccache;
    krb5_principal serverp = 0;
    krb5_address **addresses = NULL;
    char *default_realm = NULL;
    char *realm = NULL;
    struct stat statbuf;
    char *flags;
    char *sp;
    krb5_get_init_creds_opt *options;
    krb5_keytab userkeytab;
    krb5_principal userprinc;
    char repbuf[BUFSIZ];
    krb5_creds usercreds;
    LDAP *ld;
    struct berval **rules;
    struct berval **keytab;
    char *dn;
    FILE *ofile;
    unsigned char *keydata;
    size_t keysize;
    int i;
    int needunlink = 0;
    char *prefix;
    int preflen = strlen(principal) + 1;

    asprintf(&prefix, "%s=", principal);

    // This is the one operation where we don't do permissions
    // checking. The code in the main body verified that the caller
    // authenticated with a host credential.

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }

    // get the keytab registered for this user and host
    // anonymous is special -- always allowed
    if (strcmp(username, "anonymous.user") == 0) {
        snprintf(repbuf, sizeof(repbuf)-1, "/etc/krb5.anonymous.keytab");
    }
    else {
        // we'll give out any credentials authorized for this user and host.
        // remember it's only the host that is asserting that this is the user,
        // but that's the best we can do.  

        // The caller can request a specific principal. If it's registered they can
        // get it. But the registration code makes sure that non-root users can't
        // register to get someone else's principal.

        // Root will be set up by admins. They should only have access to non-critical
        // principals, except on secure machines.

        int found = 0;

        ld = krb_ldap_open(context, service, myhostname, default_realm);

        if (!ld) {
            mylog(LOG_ERR, "ldap open failed");
            return GENERIC_ERR;
        }

        r = getLdapData(context, ld, default_realm,  username, &rules, &keytab, &dn);
        if (r) {
            mylog(LOG_ERR, "get ldap data failed");
            return GENERIC_ERR;
        }

        if (rules) {
            for (i = 0; rules[i]; i++) {

                char *line = rules[i]->bv_val;

                char *ch, *princp;

                // if ends in \n, kill the \n
                if (line[strlen(line)-1] == '\n')
                    line[strlen(line)-1] = '\0';

                // first item is host
                ch = strchr(line, ':');
                if (!ch)
                continue;
                *ch = '\0';
                // line - ch is host; verify right host
                if (strcmp(line, hostname) != 0 && strcmp(line, "*") != 0)
                    continue;

                princp = ch+1;
                // next item is principal
                ch = strchr(princp, ':');
                // end of line is OK
                if (ch)
                    *ch = '\0';
                if (strcmp(princp, principal) != 0)
                    continue;

                // got it
                found = 1;
                // rest is flags
                if (ch)
                    flags = ch+1;
                else
                    flags = "";
                break;
            }
            
        }

        if (!found)
            return NOKEYTAB_ERR;            

        // Found 

        // we've got a rule that matches. Now need keytab in order to
        // generate the credentials

        // make sure we got one from ldap. if there's a rule there should
        // be a key table, so this is unusual
        if (keytab == NULL || keytab[0] == NULL) {
            mylog(LOG_ERR, "no keytab attribute in ldap for %s", username);
            return GENERIC_ERR;
        }

        found = 0;

        for (i = 0; keytab[i] != NULL; i++) {
            char *thistext;
            thistext = keytab[i]->bv_val;
            if (strncmp(thistext, prefix, preflen) == 0) {
                found = 1;
                break;
            }
        }

        if (!found) {
            mylog(LOG_ERR, "missing key table for %s %s", principal, username);
            return GENERIC_ERR;
        }

        // found keytab for this principal
        // i is the right index
       // + preflen to skip principal= and get to the actual keytable
        keydata = malloc(keytab[i]->bv_len);
        keysize = keytab[i]->bv_len;
        if (base64decode (keytab[0]->bv_val + preflen, strlen(keytab[0]->bv_val + preflen), keydata, &keysize)) {
            mylog(LOG_ERR, "base64 decode failed");
            return GENERIC_ERR;
        }

        // keytab is now in keydata
        // write it into a file, since kerberos expects keytabs to be in files

        snprintf(repbuf, sizeof(repbuf)-1, "/tmp/credserv.keytab.%lu", (unsigned long) getpid());

        ofile = fopen(repbuf, "w");
        if (!ofile) {
            mylog(LOG_ERR, "fopen failed: %s", repbuf);
            return GENERIC_ERR;
        }

        if (fwrite(keydata, keysize, 1, ofile) != 1) {
            mylog(LOG_ERR, "keytab write failed");
            return GENERIC_ERR;
        }

        fclose(ofile);
        needunlink = 1;  // this is temp file

    }

    // keytab, either the anonymous one or the user's is now in a file 
    // file name in repbuf

    // request is authorized
    // now have filename of keytab in repbuf

    if (stat(repbuf, &statbuf) != 0) {
        // don't log an error. This is normal if user is confused.
        return NOKEYTAB_ERR;
    }

    if ((r = krb5_kt_resolve(context, repbuf, &userkeytab))) {
        // file is there but we can't read it as a keytab. Something odd
        mylog(LOG_ERR, "unable to get keytab for user %s %s", username, error_message(r));
        goto cleanup;
    }

    // if principal has @ in it, separate principal and realm, else default realm
    sp = strchr(principal, '@');
    if (sp) {
        *sp = '\0';
        realm = sp+1;
    } else
        realm = default_realm;

    if ((r = krb5_build_principal(context, &userprinc, strlen(realm), realm, principal, NULL))) {
        mylog(LOG_ERR, "unable to make principal from %s %s", principal, error_message(r));
        goto cleanup;
    }

    // now we have a principal in userprinc
    // we also have a keytab to use to generate credentials

    // create options structure for new credentials
    if ((r = krb5_get_init_creds_opt_alloc(context, &options))) {
        mylog(LOG_ERR, "unable to allocate options %s", error_message(r));
        goto cleanup;
    }

    // these credentials should use our IP address. The address will be adjusted when forwarding

    if ((r =krb5_os_localaddr(context, &addresses))) {
        mylog(LOG_ERR, "unable to get our addresses %s", error_message(r));
        goto cleanup;
    }

    krb5_get_init_creds_opt_set_address_list(options, addresses);

    // finally, get the credentials from the keytab that was registered
    if ((r = krb5_get_init_creds_keytab(context, &usercreds, userprinc, userkeytab, 0,  NULL, options))) {
        mylog(LOG_ERR, "unable to make credentials for user from keytab %s %s %s", username, repbuf, error_message(r));
        goto cleanup;
    }

    // put it in a temporary cache, since we're just going to forward it
    if ((r = krb5_cc_new_unique(context, "MEMORY", "/tmp/jjjjj", &ccache))) {
        mylog(LOG_ERR, "unable to make credentials file for user %s %s", username, error_message(r));
        goto cleanup;
    }

    if ((r = krb5_cc_initialize(context, ccache, userprinc))) {
        mylog(LOG_ERR, "unable to initialize credentials file for user %s %s", username, error_message(r));
        goto cleanup;
    }

    if ((r = krb5_cc_store_cred(context, ccache, &usercreds))) {
        mylog(LOG_ERR, "unable to store user credentials in cache for user %s %s", username, error_message(r));
        goto cleanup;
    }

    if ((r = krb5_sname_to_principal(context, myhostname, NULL,
				     KRB5_NT_SRV_HST, &serverp))) {
      mylog(LOG_ERR, "could not make server principal %s",error_message(r));
      goto cleanup;
    }

    // for the forward, we need the local IP addresses in auth_content.
    /* fd is always 0 because the real one gets put onto 0 by dup2 */
    if ((r = krb5_auth_con_genaddrs(context, auth_context, 0,
			    KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR))) {
      mylog(LOG_ERR, "could not get local full address %s",error_message(r));
      goto cleanup;
    }

    // Now we've got all the info to generate the forwarded credential.
    // This operation takes a credential appropriate for our system and
    // turns it into one appropriate for hostname.
    // Normally we don't want it forwardable, to minimze the damage if someone
    // can become root on the client system. But sometimes we need it forwardable.
    // So an admin user can set the "F" flag in the INDEX entry.

    if ((r = krb5_fwd_tgt_creds(context, auth_context, hostname, userprinc, serverp,
			        ccache, (strchr(flags, 'F') != NULL), data))) {
      mylog(LOG_ERR, "error getting forwarded credentials for user %s %s",username, error_message(r));
      goto cleanup;
    }

    if (needunlink)
        unlink(repbuf);

    // good return. The new, adjusted credential is in data. It's actually
    // a KRB-CRED message, which has the most sensitive part encrypted
    // in the session key. krb5_rd_cred in the client reads this message and
    // produces the actual credential.

    mylog(LOG_INFO, "credserv returning credentials for %s for user %s to host %s", principal, username, hostname);

    return 0;
    // since we forked, we're not actually doign cleanup
 cleanup:
    if (needunlink)
        unlink(repbuf);

    return GENERIC_ERR;

}

// list credentials for user username.
// cname is the principal that they are authenticated as.

char *
listcreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *myhostname, char *hostname, char *service, krb5_data *outdata, char *clientp) {

    char *default_realm = NULL;
    struct princlist *princs = NULL;
    int printsize = 0;
    char princbuf[1024];
    char *outptr;
    char *outstring;
    int r;
    struct princlist *princitem;
    struct hostlist *hostitem;
    struct berval **rules;
    struct berval **keytab;
    char *dn;
    int i;
    LDAP *ld;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }
    
    // Check permission
    // privileged user can see anything.
    // Root if it hasn't authenticated as a privileged user can't do anything.
    // Otherwise, user can see only its own data.

    snprintf(princbuf, sizeof(princbuf)-1, "%s@%s", username, default_realm);
    if (isprived(clientp)) {
        ;  // allow anything
    } else if (strcmp("root", username) == 0) {
        // Root is generally not a valid credential
        return "Currently we don't support this function for root";
    } else if (strcmp(princbuf, clientp) != 0) {
        // non-root, user they're requested info on must agree with authenticated principal
        mylog(LOG_ERR, "user %s asked to list user %s", username, clientp);
        return GENERIC_ERR;
    } else {
        // authenticated as normal user, show then all hosts
        hostname = NULL;
    }

    ld = krb_ldap_open(context, service, myhostname, default_realm);

    if (!ld) {
        mylog(LOG_ERR, "ldap open failed");
        return GENERIC_ERR;
    }

    r = getLdapData(context, ld, default_realm,  username, &rules, &keytab, &dn);
    if (r) {
        mylog(LOG_ERR, "get ldap data failed");
        return GENERIC_ERR;
    }

    // parse the file and collect data. Since we want to be able
    // to sort it, we put the data into a list of malloc'ed structures
    // We also collect the sizes of the strings we'll eventually output,
    // so we know how big a space to malloc for the final output.

    if (rules) {
        for (i = 0; rules[i]; i++) {
            char *buffer = rules[i]->bv_val;
            char *ch, *princp, *flags;
        
            // if ends in \n, kill the \n
            if (buffer[strlen(buffer)-1] == '\n')
                buffer[strlen(buffer)-1] = '\0';
            
            // first item is host
            ch = strchr(buffer, ':');
            if (!ch)
                continue;
            *ch = '\0';
            // buffer is now host

            // only allowed to see one host. if it's a different one, skip it
            //        if (hostname && strcmp(hostname, buffer) != 0)
            //            continue;
            
            princp = ch+1;
            // next item is principal
            ch = strchr(princp, ':');
            // end of line is OK
            if (ch)
                *ch = '\0';
            // princp is now principal
        
            if (ch)
                flags = ch+1;
            else
                flags = "";

            // look for our principal in the list
            for (princitem = princs; princitem && strcmp(princitem->principal, princp) ; princitem = princitem->next)
            ;
            // if we didn't find it, create a new entry
            if (!princitem) {
                princitem = malloc(sizeof(struct princlist));
                princitem->principal = malloc(strlen(princp) + 1);
                strcpy(princitem->principal, princp);
                princitem->next = princs;
                princitem->hosts = NULL;
                princs = princitem;
                printsize += strlen(princp) + 2;
            }
            // princitem is now the principal. See if we've already got this host
            for (hostitem = princitem->hosts; hostitem && strcmp(hostitem->host, buffer) ; hostitem = hostitem->next)
                ;
            // if we didn't find it, create a new entry
            if (!hostitem) {
                hostitem = malloc(sizeof(struct hostlist));
                hostitem->host = malloc(strlen(buffer) + 1);
                strcpy(hostitem->host, buffer);
                hostitem->flags = malloc(strlen(flags) + 1);
                strcpy(hostitem->flags, flags);
                hostitem->next = princitem->hosts;
                princitem->hosts = hostitem;
                printsize += strlen(buffer) + 2;
                if (strlen(flags) > 0)
                    printsize += strlen(flags) + 1;
            }
        }
    }

    /* now print the result. format
 principal: host, host\n
 principal: host, host\n
     for each principal, size of principal + 2
     for each host, size of host + 2 */

    // go through the list of data and print into a buffer

    if (printsize == 0) {
        printsize = 1;  // will put a single newline
    }        

    outptr = malloc(printsize + 1);
    outstring = outptr;
    
    for (princitem = princs; princitem ; princitem = princitem->next) {
        outptr += sprintf(outptr, "%s: ", princitem->principal);
        for (hostitem = princitem->hosts; hostitem ; hostitem = hostitem->next) { 
            char flagbuf[20];
            char *flags;
            if (strlen(hostitem->flags) > 0) {
                snprintf(flagbuf, sizeof(flagbuf), ":%s", hostitem->flags);
                flags = flagbuf;
            } else
                flags = "";
            if (hostitem->next)
                outptr += sprintf(outptr, "%s%s, ", hostitem->host, flags);
            else
                outptr += sprintf(outptr, "%s%s\n", hostitem->host, flags);
        }
    }
    
    // if there's output, the sprintf will have added the terminating null
    // but if not the string is uninitialized
    if (printsize == 1)
        strcpy(outstring, "\n");

    outdata->data = outstring;
    outdata->length = strlen(outstring);
    return NULL;

}

// register credentials for user username.
// cname is the principal that they are authenticated as.

char *
registercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *myhostname, char *hostname, char *realhost, char *service, krb5_data *outdata, char *clientp, krb5_ticket *ticket, char *flags) {

    char *default_realm = NULL;
    int r;
    FILE *keytabf;
    char princname[1024];
    long fsize;
    int found = 0;
    pid_t child;
    int status = 0;
    struct berval **rules;
    struct berval **keytab;
    struct berval newkeytab;
    char *keydata;
    char *dn;
    int i;
    LDAP *ld;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }
    
    // user has asked to register credentials for username and principal on host they came from.
    // Check permission. If they are authenticated as a privileged user let them
    // do anything. Otherwise they can only authorize their own principal on the
    // specific machine where they are coming from. (Otherwise if root found
    // credentials lying around they could register the user for another system
    // where the hacker has control.)

    // There's one more protection. I'm concerned that a user who has a long-running
    // session could be compromised by root getting to their credential. So the client
    // gets a new ticket. I have no obvious way to know that the ticket they're presenting
    // is that one, but I can check that it was obtained within the last 30 sec.

    snprintf(princname, sizeof(princname)-1, "%s@%s", username, default_realm);
    if (isprived(clientp)) {
        ;  // allow anything
    } else if (strcmp("root", username) == 0) {
        // root generally isn't a valid principal
        return "Currently we don't support this function for root";
    } else if (strcmp(princname, clientp) != 0 || strcmp(princname, principal) != 0) {
        // non-root, user must agree with authenticated principal
        mylog(LOG_ERR, "user %s asked to register user %s principal %s host %s", clientp, username, principal, hostname);
        return GENERIC_ERR;
    } else if (!isrecent(ticket)) {
        mylog(LOG_ERR, "user %s asked to register user %s principal %s host %s", clientp, username, principal, hostname);
        return "Your credentials are too old. Is your computer not synchronized?";
    } else {
        // normal user can't set flags
        flags = "";
        // and they get data from the real host only
        hostname = realhost;
    }

    ld = krb_ldap_open(context, service, myhostname, default_realm);

    if (!ld) {
        mylog(LOG_ERR, "ldap open failed");
        return GENERIC_ERR;
    }

    r = getLdapData(context, ld, default_realm,  username, &rules, &keytab, &dn);
    if (r) {
        mylog(LOG_ERR, "get ldap data failed");
        return GENERIC_ERR;
    }

    if (rules) {
        for (i = 0; rules[i]; i++) {
            char *buffer = rules[i]->bv_val;
            char *ch;
            char *princp;

            // first item is host
            ch = strchr(buffer, ':');
            if (!ch)
                continue;
            *ch = '\0';
            // buffer is now host

            if (strcmp(buffer,hostname) != 0) 
                continue;
        
            princp = ch+1;
            // next item is principal
            ch = strchr(princp, ':');
            // end of line is OK
            if (ch)
                *ch = '\0';
            // princp is now principal
        
            if (strcmp(princp,principal) != 0)
                continue;
            
            found = 1;
            break;
        }
    }

    // if it's not there, add it
    if (!found) {
        char *newrule;
        mylog(LOG_DEBUG, "user %s principal %s host %s not in INDEX, adding", username, principal, hostname);

        if (strcmp(flags, "") != 0)
            asprintf(&newrule, "%s:%s:%s", hostname, principal, flags);
        else
            asprintf(&newrule, "%s:%s", hostname, principal);

        r = addRule(ld, dn, newrule);

        if (r != 0) {
            mylog(LOG_DEBUG, "unable to add new rule for %s", username);
            return "unable to add new rule";
        }
    }

    // now recreate the keytable. do this even if index entry existed. Because keytables
    // are invalidated when the user changes their password, we need a way for them to
    // update the keytable. So reregistering for a host will get the keytable again.

    snprintf(princname, sizeof(princname)-1, "/tmp/credserv.keytab.%lu", (unsigned long) getpid());

    // for the moment the only way to generate a key table for another user is
    // to be on the Kerberos server and use kadmin.local. This will change in new
    // versions of kerberos, where kadmin can be authorized to do it remotely.
    // But for now, we call kadmin.local in a fork.

    mylog(LOG_DEBUG, "/sbin/kadmin.local ktadd -norandkey -k %s %s", princname, principal);

    child = fork();

    if (child == 0) {
        int fd;

        // in child
        for ( fd=getdtablesize(); fd>=0; --fd) 
            close(fd);

        fd = open("/dev/null",O_RDWR, 0);
        
        if (fd != -1) {          
            dup2 (fd, STDIN_FILENO);
            dup2 (fd, STDOUT_FILENO);
            dup2 (fd, STDERR_FILENO);
            if (fd > 2)
                close (fd);
        }
        execl("/sbin/kadmin.local", "kadmin.local", "ktadd", "-norandkey", "-k", princname, principal, NULL);
        mylog(LOG_ERR, "exec of kadmin.local failed");

    }

    // in parent

    waitpid(child, &status, 0);

    if (WEXITSTATUS(status)) {
        mylog(LOG_ERR, "kadmin ktadd failed for %u %s", WEXITSTATUS(status), principal);
        return "unable to create key table -- kadmin failed";
    }

    // keytab is now in a file, name in princname
    // read it in and put it into ldap

    // read it
    keytabf = fopen(princname, "r");
    if (!keytabf) {
        mylog(LOG_ERR, "unable to create key table for %s", principal);
        return "unable to create key table";
    }
    fseek(keytabf, 0, SEEK_END);
    fsize = ftell(keytabf);
    fseek(keytabf, 0, SEEK_SET);  //same as rewind(f);

    keydata = malloc(fsize + 1);
    fread(keydata, fsize, 1, keytabf);
    fclose(keytabf);
    unlink(princname);
    
    // keytab is now in keydata.
    // base64 encode into the newkeytab berval

    // set bv_val to principal=keytab
    newkeytab.bv_val = malloc(strlen(principal) + 3*fsize + 2);
    strcpy(newkeytab.bv_val, principal);
    strcat(newkeytab.bv_val, "=");
    if (base64encode(keydata, fsize, newkeytab.bv_val + strlen(newkeytab.bv_val), 3*fsize+1)) {
        mylog(LOG_ERR, "base64 encode failed");
        return "base64 encode failed";
    }
    newkeytab.bv_len = strlen(newkeytab.bv_val);

    // have the keytab in newkeytab. write it into ldap

    r = replaceKeytab(ld, dn, keytab, &newkeytab);
    if (r != 0) {
        mylog(LOG_ERR, "unable to replace keytab in ldap");
        return "unable to replace keytab in ldap";
    }

    // yeah! it worked

    mylog(LOG_INFO, "registered %s:%s:%s for user %s", hostname, principal, flags, username);

    outdata->data = "ok\n";
    outdata->length = 3;
    return NULL;

}

// unregister credentials for user username.
// cname is the principal that they are authenticated as.

char *
unregistercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *myhostname, char *hostname, char *realhost, char *service, krb5_data *outdata, char *clientp, krb5_ticket *ticket) {

    char *default_realm = NULL;
    char buffer[1024];
    int r;
    int found = 0;
    int principal_found = 0;
    struct berval **rules;
    struct berval **keytab;
    char *dn;
    int i;
    LDAP *ld;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }
    
    // see register for a discussion of authorization

    snprintf(buffer, sizeof(buffer)-1, "%s@%s", username, default_realm);
    if (isprived(clientp)) {
        ;  // allow anything for admin user
    } else if (strcmp("root", username) == 0) {
        // root generally isn't a valid principal
        return "Currently we don't support this function for root";
    } else if (strcmp(buffer, clientp) != 0 || strcmp(buffer, principal) != 0) {
        // non-root, user must agree with authenticated principal
        mylog(LOG_ERR, "user %s asked to register user %s principal %s host %s", clientp, username, principal, hostname);
        return GENERIC_ERR;
    } else if (!isrecent(ticket)) {
        mylog(LOG_ERR, "user %s asked to register user %s principal %s host %s", clientp, username, principal, hostname);
        return "Your credentials are too old. Is your computer not synchronized?";
        // everything matches
    } else {
        // normal user can only unregister on host they're coming from
        hostname = realhost;
    }

    ld = krb_ldap_open(context, service, myhostname, default_realm);

    if (!ld) {
        mylog(LOG_ERR, "ldap open failed");
        return GENERIC_ERR;
    }

    r = getLdapData(context, ld, default_realm,  username, &rules, &keytab, &dn);
    if (r) {
        mylog(LOG_ERR, "get ldap data failed");
        return GENERIC_ERR;
    }

    if (rules) {
        for (i = 0; rules[i]; i++) {
            char *line = rules[i]->bv_val;
            char *ch, *ch1;
            char *princp;
        
            // first item is host
            ch = strchr(line, ':');
            if (!ch)
                continue;
            *ch = '\0';
            // line is now host

            princp = ch+1;
            // next item is principal
            ch1 = strchr(princp, ':');
            // end of line is OK
            if (ch1)
                *ch1 = '\0';
            // princp is now principal
        
            if (strcmp(princp,principal) != 0)
                continue;
            
            if (strcmp(line,hostname) != 0) {
                // principal found for something other than specified host
                // that means we still need it
                principal_found = 1;
                continue;
            }

            // put the line back
            *ch = ':';
            if (ch1)
                *ch1 = ':';

            // both principal and host match. found the actual entry
            found = 1;
            break;
        }

    }

    // if we found the requested entry, delete from ldap
    if (found) {
        if (deleteRule(ld, dn, rules[i]->bv_val)) {
            mylog(LOG_ERR, "unable to delete rule from ldap");
            return GENERIC_ERR;
        }
    } else {
        mylog(LOG_DEBUG, "user %s principal %s host %s not in INDEX, no need to remove", username, principal, hostname);
    }

    // if there's no references to this principal left in the file,
    // remove the keytab
    if (!principal_found) {
        deleteKeytab(ld, dn, keytab, principal);
        mylog(LOG_DEBUG, "removed keytab for %s", principal);
    }

    mylog(LOG_ERR, "unregistered %s:%s for user %s", hostname, principal, username);

    outdata->data = "ok\n";
    outdata->length = 3;
    return NULL;

}
