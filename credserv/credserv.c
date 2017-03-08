/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* appl/sample/sserver/sserver.c */
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

/*
 * Sample Kerberos v5 server.
 *
 * sample_server:
 * A sample Kerberos server, which reads an AP_REQ from a TCP socket,
 * decodes it, and writes back the results (in ASCII) to the client.
 *
 * Usage:
 * sample_server servername
 *
 * file descriptor 0 (zero) should be a socket connected to the requesting
 * client (this will be correct if this server is started by inetd).
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

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sample.h"

#define CONFFILE "/etc/credserv.conf"
// contains privileged principals

extern krb5_deltat krb5_clockskew;

int debug = 0;

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

int isprived(char *principal);

// read the file here, since this is only called once per
// transaction, for transactions that aren't expected to be
// very common.
int isprived(char *principal) {
    FILE *conffile;
    char line[1024];

    conffile = fopen(CONFFILE, "r");
    if (!conffile) {
        mylog(LOG_ERR, "can't read %s", CONFFILE);
        return 0;
    }

    while (fgets(line, sizeof(line), conffile)) {
        if (line[strlen(line)-1] == '\n')
            line[strlen(line)-1] = '\0';
        if (strcmp(principal, line) == 0) {
            mylog(LOG_DEBUG, "%s is privileged", principal);
            fclose(conffile);
            return 1;
        }
    }
    fclose(conffile);
    return 0;
}

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

    // we want to make sure that the user got fresh credentials,
    // so root can't use something lying around. 30 sec allows
    // for some clock skew and processing time. Shorter might be
    // better.
    if ((now - times.authtime) > 30) {
        mylog(LOG_ERR, "ticket is too old");
        return 0;
    }

    return 1;

}

char *getcreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *hostname, krb5_data *data);
char *listcreds(krb5_context context, krb5_auth_context  auth_context, char * username, char *principal, char *hostname, krb5_data *data, char *cname);
char *registercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *hostname, char *realhost, krb5_data *outdata, char *clientp, krb5_ticket *ticket, char * flags);
char *unregistercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *hostname, char *realhost, krb5_data *outdata, char *clientp, krb5_ticket *ticket);

int
main(int argc, char *argv[])
{
    krb5_context context;
    krb5_auth_context auth_context = NULL;
    krb5_ticket * ticket;
    struct sockaddr_in peername;
    GETPEERNAME_ARG3_TYPE  namelen = sizeof(peername);
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
    struct hostent* host;
    // args from kgetcred
    char op; // operation: G - get creds, S - set creds; future delete and list
    char *username;
    char *principal;
    char *hostname;
    char *flags;
    char *realhost;
    krb5_creds usercreds;
    krb5_data data;
    char *errmsg = GENERIC_ERR;
    int i;
    int found = 0;
    struct in_addr **addr_list;

    // in case we're run by a user from the command line, get a known environment
    clearenv();

    memset(&usercreds, 0, sizeof(usercreds));


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

    if (keytab == NULL) {
        if ((retval = krb5_kt_resolve(context, "/etc/krb5.keytab", &keytab))) {
            com_err(progname, retval, "while resolving keytab file /etc/krb5.keytab");
            exit(2);
        }
    }

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
        struct sockaddr_in sockin;

        if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
            mylog(LOG_ERR, "socket: %m");
            exit(3);
        }
        /* Let the socket be reused right away */
        (void) setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on,
                          sizeof(on));

        sockin.sin_family = AF_INET;
        sockin.sin_addr.s_addr = 0;
        sockin.sin_port = htons(port);
        if (bind(sock, (struct sockaddr *) &sockin, sizeof(sockin))) {
            mylog(LOG_ERR, "bind: %m");
            exit(3);
        }
        if (listen(sock, 1) == -1) {
            mylog(LOG_ERR, "listen: %m");
            exit(3);
        }
        signal(SIGCHLD, SIG_IGN);
        while (1) {
            if ((acc = accept(sock, (struct sockaddr *)&peername, &namelen)) == -1){
                mylog(LOG_ERR, "accept: %m");
                exit(3);
            }
            if (fork()) {
                ; // in parent
            } else {
                break;  // in child -- leave loop
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
        if (getpeername(0, (struct sockaddr *)&peername, &namelen) < 0) {
            mylog(LOG_DEBUG, "getpeername: %m");
            exit(1);
        }
        sock = 0;
    }

    mylog(LOG_DEBUG, "connection from %s", inet_ntoa(peername.sin_addr));

    retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
                           SAMPLE_VERSION, server,
                           0,   /* no flags */
                           keytab,      /* default keytab is NULL */
                           &ticket);
    if (retval) {
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }

    // get arguments from kgetcred: operation, username and principal

    // op
    if ((retval = net_read(sock, (char *)&op, 1)) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }

    // username
    if ((retval = net_read(sock, (char *)&xmitlen,
                           sizeof(xmitlen))) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }
    xmitlen = ntohs(xmitlen);
    if (!(username = (char *)malloc((size_t) xmitlen + 1))) {
        mylog(LOG_ERR, "no memory while allocating buffer to read from client");
        exit(1);
    }
    if ((retval = net_read(sock, (char *)username,
                           xmitlen)) <= 0) {
        mylog(LOG_ERR, "connection abort while reading data from client");
        exit(1);
    }
    username[xmitlen] = '\0';

    // principal
    if ((retval = net_read(sock, (char *)&xmitlen,
                           sizeof(xmitlen))) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }
    xmitlen = ntohs(xmitlen);
    if (!(principal = (char *)malloc((size_t) xmitlen + 1))) {
        mylog(LOG_ERR, "no memory while allocating buffer to read from client");
        exit(1);
    }
    if ((retval = net_read(sock, (char *)principal,
                           xmitlen)) <= 0) {
        mylog(LOG_ERR, "connection abort while reading data from client");
        exit(1);
    }
    principal[xmitlen] = '\0';

    // flags
    if ((retval = net_read(sock, (char *)&xmitlen,
                           sizeof(xmitlen))) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }
    xmitlen = ntohs(xmitlen);
    if (!(flags = (char *)malloc((size_t) xmitlen + 1))) {
        mylog(LOG_ERR, "no memory while allocating buffer to read from client");
        exit(1);
    }
    if (xmitlen > 0) {
        if ((retval = net_read(sock, (char *)flags,
                               xmitlen)) <= 0) {
            mylog(LOG_ERR, "connection abort while reading data from client");
            exit(1);
        }
    }
    flags[xmitlen] = '\0';

    // hostname
    if ((retval = net_read(sock, (char *)&xmitlen,
                           sizeof(xmitlen))) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }
    xmitlen = ntohs(xmitlen);
    if (!(hostname = (char *)malloc((size_t) xmitlen + 1))) {
        mylog(LOG_ERR, "no memory while allocating buffer to read from client");
        exit(1);
    }
    if (xmitlen > 0) {
        if ((retval = net_read(sock, (char *)hostname,
                               xmitlen)) <= 0) {
            mylog(LOG_ERR, "connection abort while reading data from client");
            exit(1);
        }
    }
    hostname[xmitlen] = '\0';

    mylog(LOG_DEBUG, "operation %c for user %s principal %s from host %s", op, username, principal, inet_ntoa(peername.sin_addr));

    /* Get client name */
    repbuf[sizeof(repbuf) - 1] = '\0';
    retval = krb5_unparse_name(context, ticket->enc_part2->client, &cname);
    if (retval){
        mylog(LOG_ERR, "unable make sense of client principal--%s", error_message(retval));
        goto cleanup;
    }

    if (op == 'G' || strncmp("host/", cname, 5) == 0)  {
        // user is authenticated as a host. verify that the request came from that host
        //otherwise we do a reverse lookup of IP. But if a host has
        //more than one name, this is mostly ikely to produce the right answer

        char *hoststart;
        char *hostend;
    
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
        if (strcmp("host", cname) != 0) {
            mylog(LOG_ERR, "request not from host %s", cname);
            goto cleanup;
        }
        host = gethostbyname(hoststart+1);
        if (!host) {
            mylog(LOG_ERR, "can't find hostname %s", hoststart + 1);
            goto cleanup;
        }

        // make sure request is actually from this host
        addr_list = (struct in_addr **)host->h_addr_list;
        for(i = 0; addr_list[i] != NULL; i++) {
            if (addr_list[i]->s_addr == peername.sin_addr.s_addr) {
                found = 1;
                break;
            }
        }
        if (!found) {
            mylog(LOG_ERR, "peer address %s doesn't match hostname %s",
                  inet_ntoa(peername.sin_addr), hoststart+1);
            goto cleanup;
        }
        *hostend = '@';  // put back punctuation so we have the whole principal again
        *hoststart = '/';
        // normalized name
        realhost = host->h_name;
    } else {
        //all we have is an ip address. just do reverse lookup
        if (getnameinfo((struct sockaddr *)&peername, namelen, hostbuf, sizeof(hostbuf), NULL, 0, NI_NAMEREQD)) {
            mylog(LOG_ERR, "can't find hostname from IP %m");
            goto cleanup;
        }        
        realhost = hostbuf;
    }
    // end principal check

    if (op == 'G') 
        errmsg = getcreds(context, auth_context, username, principal, realhost, &data);
    else if (op == 'L') 
        errmsg = listcreds(context, auth_context, username, principal, realhost, &data, cname);
    else if (op == 'R') 
        errmsg = registercreds(context, auth_context, username, principal, hostname, realhost, &data, cname, ticket, flags);
    else if (op == 'U') 
        errmsg = unregistercreds(context, auth_context, username, principal, hostname, realhost, &data, cname, ticket);

    if (errmsg == NULL) {
        char status[1];
        mylog(LOG_DEBUG, "returning data to client %s for user %s length %d", inet_ntoa(peername.sin_addr), username, data.length);

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
        char status[1];
        status[0] = 'e'; // error message
        mylog(LOG_DEBUG, "returning error to client %s for user %s %s", inet_ntoa(peername.sin_addr), username, errmsg);

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

// returns NULL if OK, else error message
char *
getcreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *hostname, krb5_data *data) {
    krb5_error_code r;
    krb5_ccache ccache;
    krb5_principal serverp = 0;
    krb5_address **addresses = NULL;
    char *default_realm = NULL;
    char *realm = NULL;
    struct stat statbuf;
    FILE *indexf;
    char *flags;
    char *sp;
    krb5_get_init_creds_opt *options;
    krb5_keytab userkeytab;
    krb5_principal userprinc;
    char repbuf[BUFSIZ];
    char hostbuf[1024];
    krb5_creds usercreds;
    struct hostent* host;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }

    // get the keytab registered for this user and host
    // anonymous is special -- always allowed
    if (strcmp(username, "anonymous.user") == 0) {
        snprintf(repbuf, sizeof(repbuf)-1, "/var/credserv/anonymous.keytab");
    }
    else {
        // we'll give out any credentials authorized for this user and host.
        // remember it's onlyt he host that is asserting that this is the user,
        // but that's the best we can do.  
        // For a 'G' operationg The caling code has verified that caller is
        // actually authenticated as the host, and the query is coming from that host.
        // At the  moment, non-root users should only have entries for their own 
        // principal.

        // Root will be set up by admins. They should only have access to non-critical
        // principals, except on secure machines.

        char line[1024];
        int found = 0;

        snprintf(repbuf, sizeof(repbuf)-1, "/var/credserv/%s/INDEX", username);
        indexf = fopen(repbuf, "r");
        // probably nothing registered
        if (indexf == NULL) 
            return NOKEYTAB_ERR;

        while (fgets(line, sizeof(line), indexf)) {
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

        fclose(indexf);

        if (!found)
            return NOKEYTAB_ERR;            

        snprintf(repbuf, sizeof(repbuf)-1, "/var/credserv/%s/%s", username, principal);

    }

    // now have filename of keytab in repbuf

    if (stat(repbuf, &statbuf) != 0) {
        // don't log an error. This is normal if user is confused.
        return NOKEYTAB_ERR;
    }

    if ((r = krb5_kt_resolve(context, repbuf, &userkeytab))) {
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

    // these credentials should be for us. The address will be adjusted when forwarding

    if ((r =krb5_os_localaddr(context, &addresses))) {
        mylog(LOG_ERR, "unable to get our addresses %s", error_message(r));
        goto cleanup;
    }

    krb5_get_init_creds_opt_set_address_list(options, addresses);

    if ((r = krb5_get_init_creds_keytab(context, &usercreds, userprinc, userkeytab, 0,  NULL, options))) {
        mylog(LOG_ERR, "unable to make credentials for user from keytab %s %s %s", username, repbuf, error_message(r));
        goto cleanup;
    }

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

    // get our hostname, normalized
    hostbuf[sizeof(hostbuf)-1] = '\0';
    gethostname(hostbuf, sizeof(hostbuf)-1);
    host = gethostbyname(hostbuf);
    if (host == NULL) {
        mylog(LOG_ERR, "hostname %s not found", hostname);
        goto cleanup;
    }
    // FQ hostname is now host->h_name                                                                

    if ((r = krb5_sname_to_principal(context, host->h_name, NULL,
				     KRB5_NT_SRV_HST, &serverp))) {
      mylog(LOG_ERR, "could not make server principal %s",error_message(r));
      goto cleanup;
    }

    /* fd is always 0 because the real one gets put onto 0 by dup2 */
    if ((r = krb5_auth_con_genaddrs(context, auth_context, 0,
			    KRB5_AUTH_CONTEXT_GENERATE_LOCAL_FULL_ADDR))) {
      mylog(LOG_ERR, "could not get local full address %s",error_message(r));
      goto cleanup;
    }

    // hack. for the moment, if root, make it forwardaable. Otherwise can't use IPA. The hope is that
    // the script will do a kdestroy at the end.

    if ((r = krb5_fwd_tgt_creds(context, auth_context, hostname, userprinc, serverp,
			        ccache, (strchr(flags, 'F') != NULL), data))) {
      mylog(LOG_ERR, "error getting forwarded credentials for user %s %s",username, error_message(r));
      goto cleanup;
    }

    // good return, output is in data
    return 0;
    // since we forked, we're not actually doign cleanup
 cleanup:

    return GENERIC_ERR;

}

// list credentials for user username.
// cname is the principal that they are authenticated as. For the moment just support principal and username match
// in the long run, privileged principals can see anyone.

char *
listcreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *hostname, krb5_data *outdata, char *clientp) {

    char *default_realm = NULL;
    char buffer[1024];
    struct princlist *princs = NULL;
    int printsize = 0;
    char *outptr;
    char *outstring;
    int r;
    FILE *indexf;
    struct princlist *princitem;
    struct hostlist *hostitem;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }
    
    // user has asked to see listing for username. The only valid principal to request it for the 
    // moment is that principal in the default realm;

    snprintf(buffer, sizeof(buffer)-1, "%s@%s", username, default_realm);
    if (isprived(clientp)) {
        ;  // allow anything
    } else if (strcmp("root", username) == 0) {
        // at some point we'll verify that the user is authenticated as an admin
        // without that I think it's a bad idea to let root on any user see what root
        // can do, particularly on all machines
        return "Currently we don't support this function for root";
    } else if (strcmp(buffer, clientp) != 0) {
        // non-root, user must agree with authenticated principal
        mylog(LOG_ERR, "user %s asked to list user %s", username, clientp);
        return GENERIC_ERR;
    } else {
        // authenticated as normal user, show then all hosts
        hostname = NULL;
    }

    // file containing authorizations
    snprintf(buffer, sizeof(buffer)-1, "/var/credserv/%s/INDEX", username);
    indexf = fopen(buffer, "r");
    // probably nothing registered
    if (indexf == NULL) 
        return NOKEYTAB_ERR;

    while (fgets(buffer, sizeof(buffer), indexf)) {
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

    fclose(indexf);

    /* now print the result. format
 principal: host, host\n
 principal: host, host\n
     for each principal, size of principal + 2
     for each host, size of host + 2 */

    outptr = malloc(printsize);
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
    
    if (strlen(outstring) == 0)
        outstring = "\n";

    outdata->data = outstring;
    outdata->length = strlen(outstring);
    return NULL;

}

// register credentials for user username.
// cname is the principal that they are authenticated as. For the moment just support principal and username match
// in the long run, privileged principals can see anyone.

char *
registercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *hostname, char *realhost, krb5_data *outdata, char *clientp, krb5_ticket *ticket, char *flags) {

    char *default_realm = NULL;
    char buffer[1024];
    char newname[1024];
    int r;
    FILE *indexf;
    int found = 0;
    pid_t child;
    int status;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }
    
    // user has asked to register credentials for username and principal on host they came from.
    // The only valid principal to request it for the moment is that principal in the default realm;

    snprintf(buffer, sizeof(buffer)-1, "%s@%s", username, default_realm);
    if (isprived(clientp)) {
        ;  // allow anything
    } else if (strcmp("root", username) == 0) {
        // at some point we'll verify that the user is authenticated as an admin
        // without that I think it's a bad idea to let root on any user see what root
        // can do, particularly on all machines
        return "Currently we don't support this function for root";
    } else if (strcmp(buffer, clientp) != 0 || strcmp(buffer, principal) != 0) {
        // non-root, user must agree with authenticated principal
        mylog(LOG_ERR, "user %s asked to register user %s principal %s host %s", clientp, username, principal, hostname);
        return GENERIC_ERR;
    } else if (!isrecent(ticket)) {
        mylog(LOG_ERR, "user %s asked to register user %s principal %s host %s", clientp, username, principal, hostname);
        return "Your credentials are too old. Is your computer not synchronized?";
    } else {
        // normal user can't set flags
        flags = "";
        // and they get the real host
        hostname = realhost;
    }

    // file containing authorizations
    snprintf(buffer, sizeof(buffer)-1, "/var/credserv/%s/INDEX", username);
    indexf = fopen(buffer, "r");

    // see if it already exists
    if (indexf) {
        while (fgets(buffer, sizeof(buffer), indexf)) {
            char *ch, *princp;
        
            // if ends in \n, kill the \n
            if (buffer[strlen(buffer)-1] == '\n')
                buffer[strlen(buffer)-1] = '\0';

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
        fclose(indexf);
    }

    if (!found) {
        int wrote;

        mylog(LOG_DEBUG, "user %s principal %s host %s not in INDEX, adding", username, principal, hostname);
        // just in case. these will fail silently if the directories exist
        mkdir("/var/credserv", 0755);
        snprintf(buffer, sizeof(buffer)-1, "/var/credserv/%s", username);
        mkdir(buffer, 0755);

        // now append entry to file
        snprintf(buffer, sizeof(buffer)-1, "/var/credserv/%s/INDEX", username);
        
        // append, file is created if it doesn't exist
        indexf = fopen(buffer, "a"); 
        if (!indexf) {
            mylog(LOG_DEBUG, "unable to open INDEX file for %s to add entry", username);
            return "unable to open INDEX file for user";
        }
        if (strcmp(flags, "") != 0)
            wrote = fprintf(indexf, "%s:%s:%s\n", hostname, principal, flags);
        else
            wrote = fprintf(indexf, "%s:%s\n", hostname, principal);
        if (wrote <= 0) {
            mylog(LOG_DEBUG, "unable to write new entry in INDEX file for %s", username);
            return "unable to add entry ton INDEX file";
        }
        fclose(indexf);
    }

    // now recreate the principal. do this even if index entry existed, just in case
    // password changed

    snprintf(buffer, sizeof(buffer)-1, "/var/credserv/%s/%s.%lu", username, principal, (unsigned long) getpid());

    child = fork();

    if (child == 0) {
        int i, fd;

        // in child
        for ( i=getdtablesize(); i>=0; --i) 
            close(i);

        fd = open("/dev/null",O_RDWR, 0);
        
        if (fd != -1) {          
            dup2 (fd, STDIN_FILENO);
            dup2 (fd, STDOUT_FILENO);
            dup2 (fd, STDERR_FILENO);
            if (fd > 2)
                close (fd);
        }

        execl("/sbin/kadmin.local", "kadmin.local", "ktadd", "-norandkey", "-k", buffer, principal, NULL);
        mylog(LOG_ERR, "exec of kadmin.local failed");

    }

    // in parent

    waitpid(child, &status, 0);

    if (WEXITSTATUS(status)) {
        mylog(LOG_ERR, "kadmin ktadd failed for %s", principal);
        return "unable to create key table -- kadmin failed";
    }

    snprintf(newname, sizeof(newname)-1, "/var/credserv/%s/%s", username, principal);

    if (rename(buffer, newname)) {
        mylog(LOG_ERR, "rename of %s to %s failed", buffer, newname);
        return "unable to put key table in the right place - rename failed";
    }

    mylog(LOG_ERR, "added %s %s to INDEX of %s, with new keytab", hostname, principal, username);

    outdata->data = "ok\n";
    outdata->length = 3;
    return NULL;

}

// register credentials for user username.
// cname is the principal that they are authenticated as. For the moment just support principal and username match
// in the long run, privileged principals can see anyone.

char *
unregistercreds(krb5_context context, krb5_auth_context auth_context, char *username, char *principal, char *hostname, char *realhost, krb5_data *outdata, char *clientp, krb5_ticket *ticket) {

    char *default_realm = NULL;
    char buffer[1024];
    char newname[1024];
    char line[1024];
    char removeline[1024];
    int r;
    FILE *indexf;
    FILE *newf;
    int found = 0;
    int principal_found = 0;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        return GENERIC_ERR;
    }
    
    // user has asked to register credentials for username and principal on host they came from.
    // The only valid principal to request it for the moment is that principal in the default realm;

    snprintf(buffer, sizeof(buffer)-1, "%s@%s", username, default_realm);
    if (isprived(clientp)) {
        ;  // allow anything
    } else if (strcmp("root", username) == 0) {
        // at some point we'll verify that the user is authenticated as an admin
        // without that I think it's a bad idea to let root on any user see what root
        // can do, particularly on all machines
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
        // normal user gets real host
        hostname = realhost;
    }

    // file containing authorizations
    snprintf(buffer, sizeof(buffer)-1, "/var/credserv/%s/INDEX", username);
    indexf = fopen(buffer, "r");

    // see if it already exists
    if (indexf) {
        while (fgets(line, sizeof(line), indexf)) {
            char *ch, *princp;
        
            // if ends in \n, kill the \n
            if (line[strlen(line)-1] == '\n')
                line[strlen(line)-1] = '\0';

            // first item is host
            ch = strchr(line, ':');
            if (!ch)
                continue;
            *ch = '\0';
            // line is now host

            princp = ch+1;
            // next item is principal
            ch = strchr(princp, ':');
            // end of line is OK
            if (ch)
                *ch = '\0';
            // princp is now principal
        
            if (strcmp(princp,principal) != 0)
                continue;
            
            if (strcmp(line,hostname) != 0) {
                // principal found for something other than specified host
                // that means we still need it
                principal_found = 1;
                continue;
            }

            // both principal and host match. found the actual entry
            found = 1;
            break;
        }
        fclose(indexf);
    }

    if (found) {
        // need to delete entry. copying index to new location then rename

        snprintf(removeline, sizeof(removeline)-1, "%s:%s", hostname, principal);
        // buffer still has real index name
        indexf = fopen(buffer, "r");
        if (!indexf) {
            mylog(LOG_ERR, "unable to open INDEX file for %s to remove entry", username);
            return "unable to open INDEX file for user";
        }
        snprintf(newname, sizeof(buffer)-1, "/var/credserv/%s/INDEX.%lu", username, (unsigned long) getpid());
        newf = fopen(newname, "w");
        if (!indexf) {
            mylog(LOG_ERR, "unable to open new copy of INDEX file for %s to remove entry", username);
            unlink(newname);
            return "unable to open new copy of INDEX file for user";
        }
        while (fgets(line, sizeof(line), indexf)) {
            char *cp;
            int colons = 0;
            
            int length = strlen(line);
        
            // for this loop, we can't change the line because we're going to have
            // to write it back out

            if (line[length-1] == '\n')
                length--;
            
            // if we have a third : just compare up to it
            for (cp = line; *cp; cp++) {
                if (*cp == ':') {
                    colons ++;
                }
                if (colons == 2) {
                    length = (cp - line);
                    break;
                }
            }
            
            if (strncmp(line, removeline, length) != 0) {
                if (fputs(line, newf) <= 0) {
                    unlink(newname);
                    mylog(LOG_ERR, "write to new copy of INDEX file failed");
                    return "error writing new INDEX file, removal has not happened";
                }
            }
        }
        fclose(indexf);
        fclose(newf);

        if (rename(newname, buffer)) {
            unlink(newname);
            mylog(LOG_ERR, "rename of %s to %s failed", newname, buffer);
            return "unable to put new INDEX file into position; removal has not happened";
        }

        mylog(LOG_DEBUG, "removed INDEX entry user %s principal %s host %s", username, principal, hostname);

    } else {
        mylog(LOG_DEBUG, "user %s principal %s host %s not in INDEX, no need to remove", username, principal, hostname);
    }

    if (!principal_found) {
        // principal not in use by other hosts
        snprintf(buffer, sizeof(buffer)-1, "/var/credserv/%s/%s", username, principal);
        unlink(buffer);
        mylog(LOG_DEBUG, "removed keytab for %s", principal);
        // failure isn't fatal, just leaves a file aroudn
    }

    outdata->data = "ok\n";
    outdata->length = 3;
    return NULL;

}
