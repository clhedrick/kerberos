/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* appl/sample/sclient/sclient.c */
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
 *
 * Sample Kerberos v5 client.
 *
 * Usage: sample_client hostname
 */

#include "port-sockets.h"
#include "krb5.h"
#include "com_err.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <pwd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <signal.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>

#include "sample.h"

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE int
#endif

#ifdef MAC
extern char** environ;
#endif

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

/*
 This is setuid, so we have to think about security. The other end needs to be able to believe who we are.
 That's why we use host/foo.cs.rutgers.edu as our principal. It lets the other end verify tht we have access
 to the keytab, which should mean we're root, and they will check to make sure we're actualy coming from that IP.

 We don't allow any arguments.

 We run setuid, read /etc/krb5.keytab and /etc/kgetcred.conf. kgetcred.conf has hostname and port. We don't want
 to allow the user to specify that, so he can't feed auth info to a system of his choice. If he's root, then he
 can read krb5.keytab anyway and protection doesn't accomplish much. In that case he can fake this program out, but
 all he can get from a user is an IP-locked non-forwardable ticket. So basically if you register a keytab for host,
 root can compromise you.
*/


int
main(int argc, char *argv[])
{
    struct addrinfo *ap, aihints, *apstart;
    int aierr;
    int sock;
    krb5_context context;
    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval, retval2;
    //krb5_ccache ccdef;
    krb5_ccache ccache;
    krb5_principal client, server, defcache_princ;
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_auth_context auth_context = 0;
    short xmitlen;
    char op = 'G';
    char *portstr;
    char *service = "credserv";
    krb5_creds ** creds = NULL;
    krb5_replay_data replay;
    char hostname[1024];
    char *principal = NULL;
    char princbuf[1024];
    struct hostent* host;
    krb5_keytab hostkeytab;
    krb5_creds hostcreds;
    char *username;
    long written;
    FILE *conffile;
    char *serverhost = NULL;
    size_t serverhostsize = 0;
    char *cp;
    struct passwd * pwd;
    char *default_realm = NULL;
    char *krb5ccname = NULL;
    unsigned debug = 0;
    int anonymous = 0;
    int ch;

    /*
     * Parse command line arguments
     *
     */
    opterr = 0;
    while ((ch = getopt(argc, argv, "dalru")) != -1) {
        switch (ch) {
        case 'd':
            debug++;
            break;
        case 'a':
            anonymous++;
            break;
        case 'l':
            op = 'L';
            break;
        case 'r':
            op = 'R';
            break;
        case 'u':
            op = 'U';
            break;
        default:
            printf("-d debug, -a get anonymous ticket\n");
            exit(1);
            break;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc > 0)
        principal = argv[0];

    //    if (argc != 2 && argc != 3 && argc != 4) {
    //        fprintf(stderr, "usage: %s <hostname> [port] [service]\n",argv[0]);
    //        exit(1);
    //    }

    // do the stuff that needs privs first, then drop them

    // Because we're setuid, get rid of anything the user has set up.
    // The one exception is KRB5CCNAME, which we want
    // because if he's got a cache it would be confusing to set up a
    // different one. His programs probably wouldn't use it.
    // Values will be put into the cache after changing to the user's 
    // uid, so it should be safe.

    krb5ccname = getenv("KRB5CCNAME");
#ifdef MAC
    environ = malloc(sizeof(char *));
    environ[0] = NULL;
#else
    clearenv();
#endif
    if (krb5ccname)
        setenv("KRB5CCNAME", krb5ccname, 1);

    conffile = fopen("/etc/kgetcred.conf", "r");
    if (conffile == NULL) {
        fprintf(stderr, "Can't find /etc/kgetcred.conf\n");
        exit(1);
    }

    getline(&serverhost, &serverhostsize, conffile);
    if (serverhost == NULL) {
        fprintf(stderr, "/etc/kgetcred.conf is empty\n");
        exit(1);
    }

    cp = strchr(serverhost, '\n');
    if (cp)
        *cp = '\0';

    retval = krb5_init_context(&context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
        exit(1);
    }

    hostname[sizeof(hostname)-1] = '\0';
    gethostname(hostname, sizeof(hostname)-1);
    host = gethostbyname(hostname);
    if (host == NULL) {
        fprintf(stderr, "hostname %s not found\n", hostname);
        exit(1);
    }
    
    if ((retval = krb5_get_default_realm(context, &default_realm))) {
        com_err(NULL, retval, "unable to get default realm");
        exit(1);
    }

    if (op == 'G' || getuid() == 0) {
        // FQ hostname is now host->h_name

        if ((retval = krb5_build_principal(context, &client, strlen(default_realm), default_realm, "host", host->h_name, NULL))) {
            com_err(NULL, retval, "unable to make principal for this host");
            exit(1);
        }

        if ((retval = krb5_kt_resolve(context, "/etc/krb5.keytab", &hostkeytab))) {
            com_err(NULL, retval, "unable to get keytab for this host");
            exit(1);
        }

        if ((retval = krb5_get_init_creds_keytab(context, &hostcreds, client, hostkeytab, 0,  NULL, NULL))) {
            com_err(NULL, retval, "unable to make credentials for host from keytab");
            exit(1);
        }

        if ((retval = krb5_cc_new_unique(context, "MEMORY", "/tmp/jjjjj", &ccache))) {
            com_err(NULL, retval, "unable to make credentials file for host");
            exit(1);
        }

        if ((retval = krb5_cc_initialize(context, ccache, client))) {
            com_err(NULL, retval, "unable to initialized credentials file for host");                                                 
            exit(1);
        }                                                                                                                        

        if ((retval = krb5_cc_store_cred(context, ccache, &hostcreds))) {                                                             
            com_err(NULL, retval, "unable to store host credentials in cache");
            exit(1);
        }

    } else {

        if ((retval = krb5_cc_default(context, &ccache))) {
            com_err(NULL, retval, "can't get your Kerberos credentials");
            exit(1);
        }

        if ((retval = krb5_cc_get_principal(context, ccache, &client))) {
            com_err(NULL, retval, "can't get principal from your Kerberos credentials");
            exit(1);
        }        

    }

    // drop privs as soon as possible
    // we ignore all user input so it's not clear how you'd exploit this program, but still, be safe
    setregid(getgid(), getgid());
    setreuid(getuid(), getuid());

    pwd = getpwuid(getuid());
    if (!pwd) {
        fprintf(stderr, "Can't find current user\n");
        exit(1);
    }
    if (anonymous)
        username = "anonymous.user";
    else
        username = pwd->pw_name;

    (void) signal(SIGPIPE, SIG_IGN);

    //if (argc > 2)
    //        portstr = argv[2];
    //    else
        portstr = "755";

    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_socktype = SOCK_STREAM;
    aihints.ai_flags = AI_ADDRCONFIG;
    aierr = getaddrinfo(serverhost, portstr, &aihints, &ap);
    if (aierr) {
        fprintf(stderr, "%s: error looking up host '%s' port '%s'/tcp: %s\n",
                argv[0], serverhost, portstr, gai_strerror(aierr));
        exit(1);
    }
    if (ap == 0) {
        /* Should never happen.  */
        fprintf(stderr, "%s: error looking up host '%s' port '%s'/tcp: no addresses returned?\n",
                argv[0], serverhost, portstr);
        exit(1);
    }

    //    if (argc > 3) {
    //        service = argv[3];
    //    }

    retval = krb5_sname_to_principal(context, serverhost, service,
                                     KRB5_NT_SRV_HST, &server);
    if (retval) {
        com_err(argv[0], retval, "while creating server name for host %s service %s",
                serverhost, service);
        exit(1);
    }

    /* set up the address of the foreign socket for connect() */
    apstart = ap; /* For freeing later */
    for (sock = -1; ap && sock == -1; ap = ap->ai_next) {
        char abuf[NI_MAXHOST], pbuf[NI_MAXSERV];
        char mbuf[NI_MAXHOST + NI_MAXSERV + 64];
        if (getnameinfo(ap->ai_addr, ap->ai_addrlen, abuf, sizeof(abuf),
                        pbuf, sizeof(pbuf), NI_NUMERICHOST | NI_NUMERICSERV)) {
            memset(abuf, 0, sizeof(abuf));
            memset(pbuf, 0, sizeof(pbuf));
            strncpy(abuf, "[error, cannot print address?]",
                    sizeof(abuf)-1);
            strncpy(pbuf, "[?]", sizeof(pbuf)-1);
       }
        memset(mbuf, 0, sizeof(mbuf));
        strncpy(mbuf, "error contacting ", sizeof(mbuf)-1);
        strncat(mbuf, abuf, sizeof(mbuf) - strlen(mbuf) - 1);
        strncat(mbuf, " port ", sizeof(mbuf) - strlen(mbuf) - 1);
        strncat(mbuf, pbuf, sizeof(mbuf) - strlen(mbuf) - 1);
        sock = socket(ap->ai_family, SOCK_STREAM, 0);
        if (sock < 0) {
            fprintf(stderr, "%s: socket: %s\n", mbuf, strerror(errno));
            continue;
        }
        if (connect(sock, ap->ai_addr, ap->ai_addrlen) < 0) {
            fprintf(stderr, "%s: connect: %s\n", mbuf, strerror(errno));
            close(sock);
            sock = -1;
            continue;
        }
        /* connected, yay! */
    }
    if (sock == -1)
        /* Already printed error message above.  */
        exit(1);
    if (debug)
        fprintf(stderr, "connected %d\n", sock);

    cksum_data.data = serverhost;
    cksum_data.length = strlen(serverhost);


    //retval = krb5_cc_default(context, &ccdef);
    //if (retval) {
    //    com_err(argv[0], retval, "while getting default ccache");
    //    exit(1);
    //}

    //retval = krb5_cc_get_principal(context, ccdef, &client);
    //if (retval) {
    //    com_err(argv[0], retval, "while getting client principal name");
    //    exit(1);
    //}

    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &sock,
                           SAMPLE_VERSION, client, server,
                           AP_OPTS_MUTUAL_REQUIRED,
                           &cksum_data,
                           NULL,
                           ccache, &err_ret, &rep_ret, NULL);

    if (op == 'G') {
        retval2 = krb5_cc_destroy(context, ccache);
        if (retval2) {
            com_err(argv[0], retval2, "deleting temporary cache");
            exit(1);
        }
    }

    // operatoin. currently just get
    if ((written = write(sock, (char *)&op,
                         1)) < 0) {
        fprintf(stderr, "write failed 1\n");
        exit(1);
    }        
    if (debug)
        fprintf(stderr, "write %c %ld\n", op, written);

    // username
    xmitlen = htons(strlen(username));
    if ((written = write(sock, (char *)&xmitlen,
                        sizeof(xmitlen))) < 0) {
        fprintf(stderr, "write failed 1\n");
        exit(1);
    }
    if (debug)
        fprintf(stderr, "write %lu\n", written);
    if ((written = write(sock, (char *)username,
                                 strlen(username))) < 0) {
        fprintf(stderr, "write failed 2\n");
        exit(1);
    }

    if (debug)
        fprintf(stderr, "write %lu\n", written);

    // principal - if not specified by user
    if (!principal) {
        // no principal specified. username
        snprintf(princbuf, sizeof(princbuf) -1, "%s@%s", username, default_realm);
        principal = princbuf;
    } else if (!strchr(principal, '@')) {
        // principal without @, add default realm
        snprintf(princbuf, sizeof(princbuf) -1, "%s@%s", principal, default_realm);
        principal = princbuf;        
    }
    xmitlen = htons(strlen(principal));
    if ((written = write(sock, (char *)&xmitlen,
                        sizeof(xmitlen))) < 0) {
        fprintf(stderr, "write failed 1\n");
        exit(1);
    }
    if (debug)
        fprintf(stderr, "write %lu\n", sizeof(xmitlen));
    if ((written = write(sock, (char *)principal,
                                 strlen(principal))) < 0) {
        fprintf(stderr, "write failed 2\n");
        exit(1);
    }

    if (debug)
        fprintf(stderr, "write %lu\n", strlen(principal));

    krb5_free_principal(context, server);       /* finished using it */
    krb5_free_principal(context, client);

    //    krb5_cc_close(context, ccdef);
    //    if (auth_context) krb5_auth_con_free(context, auth_context);

    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
        com_err(argv[0], retval, "while using sendauth");
        exit(1);
    }

    if (retval == KRB5_SENDAUTH_REJECTED) {
        /* got an error */
        fprintf(stderr, "sendauth rejected, error reply is:\n\t\"%*s\"\n",
               err_ret->text.length, err_ret->text.data);
    } else if (rep_ret) {
        int isError = 0;
        char status[1];

        /* got a reply */
        krb5_free_ap_rep_enc_part(context, rep_ret);

        if (debug)
            fprintf(stderr, "sendauth succeeded, reply is:\n");
        if ((retval = net_read(sock, (char *)status, 1)) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            com_err(argv[0], errno, "while reading data from server");
            exit(1);
        }
        if (status[0] == 'e')
            isError = 1;

        if ((retval = net_read(sock, (char *)&xmitlen,
                               sizeof(xmitlen))) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            com_err(argv[0], errno, "while reading data from server");
            exit(1);
        }
        recv_data.length = ntohs(xmitlen);
        if (!(recv_data.data = (char *)malloc((size_t) recv_data.length + 1))) {
            com_err(argv[0], ENOMEM,
                    "while allocating buffer to read from server");
            exit(1);
        }
        if ((retval = net_read(sock, (char *)recv_data.data,
                               recv_data.length)) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            com_err(argv[0], errno, "while reading data from server");
            exit(1);
        }

        recv_data.data[recv_data.length] = '\0';

        if (isError) {
            fprintf(stderr, "Error: %s\n", recv_data.data);
            exit(1);
        }

        if (op == 'G') {
            // replay protection doens't make sense for a client, and I don't want to set up a cache
            krb5_auth_con_setflags(context, auth_context, 0);

            retval = krb5_rd_cred(context, auth_context, &recv_data, &creds, &replay);
            if (retval) {
                com_err(NULL, retval, "unable to read returned credentials");
                exit(1);
            }

            if ((retval = krb5_cc_default(context, &ccache))) {
                com_err(NULL, retval, "unable to get default credentials cache");
                exit(1);
            }

            if (krb5_cc_get_principal(context, ccache, &defcache_princ)) {
                // cache not set up
                retval = krb5_cc_initialize(context, ccache, creds[0]->client);
                if (retval) {
                    com_err(NULL, retval, "unable to initialize credentials file");
                    exit(1);
                }
            }

            if ((retval = krb5_cc_store_cred(context, ccache, creds[0]))) {
                com_err(NULL, retval, "unable to store credentials in cache");
                exit(1);
            } 

            // output will be used in scripts to set KRB5CCNAME
            printf("%s:%s\n",krb5_cc_get_type(context, ccache),krb5_cc_get_name(context, ccache));
            krb5_cc_close(context, ccache);

            krb5_free_tgt_creds(context, creds);

        } else {
            // list -- just print the data
            printf("%s\n", recv_data.data);
        }

        free(recv_data.data);
    } else {
        com_err(argv[0], 0, "no error or reply from sendauth!");
        exit(1);
    }
    // no attempt to free everything, since the program is about to exit
    freeaddrinfo(apstart);
    krb5_free_context(context);
    exit(0);
}
