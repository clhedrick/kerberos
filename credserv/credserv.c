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
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <sys/stat.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sample.h"

extern krb5_deltat krb5_clockskew;

int debug = 0;

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
    char hostname[1024];
     struct hostent* host;
    char *username;
    char *hostp;

    krb5_principal userprinc;
    krb5_creds usercreds;
    krb5_keytab userkeytab;
    krb5_get_init_creds_opt *options;
    int gotcred = 0;
    krb5_data data;
    char *errmsg = GENERIC_ERR;
    int root = 0;


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
        int i;
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

    mylog(LOG_DEBUG, "requesting ticketm for %s %s", username, inet_ntoa(peername.sin_addr));

    /* Get client name */
    repbuf[sizeof(repbuf) - 1] = '\0';
    retval = krb5_unparse_name(context, ticket->enc_part2->client, &cname);
    if (retval){
        mylog(LOG_ERR, "unable make sense of client principal--%s", error_message(retval));
        goto cleanup;
    }

    // check that the client principal is valid and that it's from the host it claims to be

    {
    char *servicep;
    char *p;
    struct in_addr **addr_list;
    int found = 0;
    int i;
    
    p = index(cname, '@');
    if (!p) {
        mylog(LOG_ERR, "principal missing @ %s", cname);
        goto cleanup;
    }
    *p = 0;
    p = index(cname, '/');
    if (!p) {
        mylog(LOG_ERR, "principal missing / %s", cname);
        goto cleanup;
    }
    hostp = p+1;
    *p = 0;
    servicep = cname;
        
    if (strcmp(servicep, "host") != 0) {
        mylog(LOG_ERR, "request not from host %s", servicep);
        goto cleanup;
    }
    
    host = gethostbyname(hostp);
    if (!host) {
        mylog(LOG_ERR, "can't find hostname %s", hostp);
        goto cleanup;
    }

    addr_list = (struct in_addr **)host->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++) {
        if (addr_list[i]->s_addr == peername.sin_addr.s_addr) {
            found = 1;
            break;
        }
    }

    if (!found) {
        mylog(LOG_ERR, "peer address %s doesn't match hostname %s",
                inet_ntoa(peername.sin_addr), hostp);
        goto cleanup;
    }
    }

    // end principal check

    {
    krb5_error_code r;
    krb5_ccache ccache;
    krb5_principal serverp = 0;
    krb5_address **addresses = NULL;
    char *default_realm = NULL;
    struct stat statbuf;

    if ((r = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(r));
        goto cleanup;
    }

    // get the keytab registered for this user and host
    // anonymous is special -- always allowed
    if (strcmp(username, "anonymous.user") == 0)
        snprintf(repbuf, sizeof(repbuf)-1, "/var/credserv/anonymous.keytab");
    else
        snprintf(repbuf, sizeof(repbuf)-1, "/var/credserv/%s-%s.keytab", username, host->h_name);

    if (stat(repbuf, &statbuf) != 0) {
        // don't log an error. This is normal if user is confused.
        errmsg = NOKEYTAB_ERR;
        goto cleanup;
    }

    if ((r = krb5_kt_resolve(context, repbuf, &userkeytab))) {
        mylog(LOG_ERR, "unable to get keytab for user %s %s", username, error_message(r));
        goto cleanup;
    }

    // get principal for the credentials we are going to return
    // if user isn't root, we use the specified user
    // but for root, the principal is probably something like scripts,
    // so we need to get it from the stored keytab. At some point we may
    // need to support more than one keytab for a host, but for now assume
    // root scripts can always run as a specific user
    if (strcmp(username, "root") != 0) {
        // non-root, use specific users
        if ((r = krb5_build_principal(context, &userprinc, strlen(default_realm), default_realm, username, NULL))) {
            mylog(LOG_ERR, "unable to make principal for user %s %s", username, error_message(r));
            goto cleanup;
        }
    } else {
        krb5_kt_cursor ktcursor;
        krb5_keytab_entry ktentry;
 
        // we need a principal. Get the first one from the keytab
        if ((r = krb5_kt_start_seq_get(context, userkeytab, &ktcursor))) {
            mylog(LOG_ERR, "unable to get cursor for keytab from %s %s", repbuf, error_message(r));
            goto cleanup;
        }

        if ((r = krb5_kt_next_entry(context, userkeytab, &ktentry, &ktcursor))) {
            mylog(LOG_ERR, "no entry in keytab %s %s", repbuf, error_message(r));
            krb5_kt_end_seq_get(context, userkeytab, &ktcursor);
            goto cleanup;
        }

        // copy the principal so we can free the entry
        if ((r = krb5_copy_principal(context, ktentry.principal, &userprinc))) {
            mylog(LOG_ERR, "unable to copy principal from key table %s %s", repbuf,  error_message(r));
            krb5_free_keytab_entry_contents(context, &ktentry);
            krb5_kt_end_seq_get(context, userkeytab, &ktcursor);
            goto cleanup;
        }

        if ((r = krb5_free_keytab_entry_contents(context, &ktentry))) {
            mylog(LOG_ERR, "unable to free entry for keytab from %s %s", repbuf, error_message(r));
        }

        if ((r = krb5_kt_end_seq_get(context, userkeytab, &ktcursor))) {
            mylog(LOG_ERR, "unable to end cursor for keytab from %s %s", repbuf, error_message(r));
        }

        root = 1;

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

    hostname[sizeof(hostname)-1] = '\0';
    gethostname(hostname, sizeof(hostname)-1);
    host = gethostbyname(hostname);
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

    if ((r = krb5_fwd_tgt_creds(context, auth_context, hostp, userprinc, serverp,
			        ccache, root, &data))) {
      mylog(LOG_ERR, "error getting forwarded credentials for user %s %s",username, error_message(r));
      goto cleanup;
    }

    gotcred = 1;

    /* Send forwarded credentials */
        //    if (!Data(ks, KRB_FORWARD, forw_creds.data, forw_creds.length)) {
        //      MessageBox(HWND_DESKTOP,
        //		 "Not enough room for authentication data", "",
        //		 MB_OK | MB_ICONEXCLAMATION);
        //}

    }

    cleanup:

    if (gotcred) {
        char status[1];
        mylog(LOG_DEBUG, "returning credentials to client %s for user %s length %d", inet_ntoa(peername.sin_addr), username, data.length);

        status[0] = 's'; // success

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
        status[0] = 'e'; // failure
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

    krb5_free_ticket(context, ticket);
    if(keytab)
        krb5_kt_close(context, keytab);
    krb5_free_principal(context, server);
    krb5_auth_con_free(context, auth_context);
    krb5_free_context(context);
    exit(0);
}
