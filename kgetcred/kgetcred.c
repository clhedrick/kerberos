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
#include <sys/select.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <syslog.h>
#include <wait.h>
#include <sys/stat.h>
#include <keyutils.h>

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

#ifdef PAM
#include <security/pam_ext.h>
static pam_handle_t *pam_handle;
#endif

static void mylog (int level, const char *format, ...)  __attribute__ ((format (printf, 2, 3)));
static void mylog (int level, const char *format, ...) {
  va_list args;
  va_start (args, format);

#ifdef PAM
  pam_vsyslog(pam_handle, level, format, args);
#else
  vprintf(format, args);
  printf("\n");
#endif

  va_end(args);
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


#ifdef PAM
int pam_kgetcred(char *krb5ccname, struct passwd * pwd, krb5_context context);

int pam_kgetcred(char *krb5ccname, struct passwd * pwd, krb5_context context)
{
#else
int main(int argc, char *argv[])
{
    char *krb5ccname = NULL;
    int ch;
    struct passwd * pwd;
    krb5_context context;
#endif

    struct addrinfo *ap, aihints, *apstart;
    int aierr;
    int sock;
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
    char realhost[1024];
    char *hostname = NULL;
    char *principal = NULL;
    int needrename = 0;
    char princbuf[1024];
    char realname[1024];
    char realccname[1024];
    char tempname[1024];
    struct hostent* host;
    krb5_keytab hostkeytab;
    krb5_creds hostcreds;
    char *username = NULL;
    long written;
    char *serverhost = NULL;
     char *default_realm = NULL;
     unsigned debug = 0;
     int anonymous = 0;
     char *clientname = NULL;
     int prived = 0;
     char *flags = "";
     krb5_data realm_data;
     key_serial_t serial;

     /*
      * Parse command line arguments
      *
      */
     opterr = 0;
#ifndef PAM
     while ((ch = getopt(argc, argv, "dalruPU:F:H:")) != -1) {
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
         case 'P':
             prived = 1;
             break;
         case 'U':
             username = optarg;
             break;
         case 'F':
             flags = optarg;
             break;
         case 'H':
             hostname = optarg;
             break;
         default:
             mylog(LOG_ERR, "-d debug, -a get anonymous ticket, -l list, -r register, -u unregister; -P prived user, -U user to operate on, -F flags, -H hostname for entry");
             exit(1);
             break;
         }
     }

     argc -= optind;
     argv += optind;

     if (argc > 0)
         principal = argv[0];
#endif

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

#ifndef PAM
    krb5ccname = getenv("KRB5CCNAME");
#ifdef MAC
    environ = malloc(sizeof(char *));
    environ[0] = NULL;
#else
    clearenv();
#endif
    if (krb5ccname) {
        setenv("KRB5CCNAME", krb5ccname, 1);
        krb5ccname = NULL;  // let environment variable handle it
    }
#endif

    if (!context) {
        retval = krb5_init_context(&context);
        if (retval) {
            mylog(LOG_ERR, "while initializing krb5 %s", error_message(retval));
            exit(1);
        }
    }

    if ((retval = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(retval));
        exit(1);
    }

    realm_data.data = default_realm;
    realm_data.length = strlen(default_realm);

    krb5_appdefault_string(context, "kgetcred", &realm_data, "server", "", &serverhost);

    if (strlen(serverhost) == 0) {
        mylog(LOG_ERR, "Please define server in the [appdefaults] section, e.g. \nkgetcred = {\n     server=hostname\n}");
        exit(1);
    }

    realhost[sizeof(realhost)-1] = '\0';
    gethostname(realhost, sizeof(realhost)-1);
    host = gethostbyname(realhost);
    if (host == NULL) {
        mylog(LOG_ERR, "hostname %s not found", hostname);
        exit(1);
    }
    
    if (hostname == NULL)
        hostname = realhost;


#ifndef PAM    
    pwd = getpwuid(getuid());
    if (!pwd) {
        mylog(LOG_ERR, "Can't find current user");
        exit(1);
    }
#endif

    // username user the action applies to, not necesarily the one we will authenticate as
    if (!username) {
        if (anonymous)
            username = "anonymous.user";
        else
            username = pwd->pw_name;
    }

    if (op == 'G') {
        // use host credentials

        // FQ hostname is now host->h_name

        if ((retval = krb5_build_principal(context, &client, strlen(default_realm), default_realm, "host", host->h_name, NULL))) {
            mylog(LOG_ERR,"unable to make principal for this host %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_kt_resolve(context, "/etc/krb5.keytab", &hostkeytab))) {
            mylog(LOG_ERR, "unable to get keytab for this host %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_get_init_creds_keytab(context, &hostcreds, client, hostkeytab, 0,  NULL, NULL))) {
            mylog(LOG_ERR, "unable to make credentials for host from keytab %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_cc_new_unique(context, "MEMORY", "/tmp/jjjjj", &ccache))) {
            mylog(LOG_ERR, "unable to make credentials file for host %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_cc_initialize(context, ccache, client))) {
            mylog(LOG_ERR, "unable to initialized credentials file for host %s", error_message(retval));
            exit(1);
        }                                                                                                                        

        if ((retval = krb5_cc_store_cred(context, ccache, &hostcreds))) {                                                                  mylog(LOG_ERR, "unable to store host credentials in cache %s", error_message(retval));
            exit(1);
        }

    } else if (op != 'L' && !prived) {
        // for prived user we have to use existing credentials, because they will be one-time and we can't deal with that
        krb5_get_init_creds_opt *opts = NULL;
        krb5_creds usercreds;

        if (!clientname)
            clientname = pwd->pw_name;

        if ((retval = krb5_build_principal(context, &client, strlen(default_realm), default_realm, clientname, NULL))) {
            mylog(LOG_ERR, "unable to make principal from your username %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_get_init_creds_opt_alloc(context, &opts))) {
            mylog(LOG_ERR, "unable to set up to get your password %s", error_message(retval));
            exit(1);
        }

        krb5_get_init_creds_opt_set_tkt_life(opts, 60); // no need to keep them around for long
        krb5_get_init_creds_opt_set_renew_life(opts, 0);
        krb5_get_init_creds_opt_set_forwardable(opts, 0);
        krb5_get_init_creds_opt_set_proxiable(opts, 0);

        if ((retval = krb5_get_init_creds_password(context, &usercreds, client, NULL, krb5_prompter_posix, NULL,
                                                   0, NULL, opts))) {
            if (retval == KRB5KRB_AP_ERR_BAD_INTEGRITY)
                mylog(LOG_ERR, "Password incorrect -- note that if you are using a one-time password this utility can't work %s", error_message(retval));
            else
                mylog(LOG_ERR, "getting initial ticket %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_cc_new_unique(context, "MEMORY", "/tmp/kkkk", &ccache))) {
            mylog(LOG_ERR, "unable to make credentials file for host %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_cc_store_cred(context, ccache, &usercreds))) { 
            mylog(LOG_ERR, "unable to store your credentials in cache %s", error_message(retval));
            exit(1);
        }

    } else {
        // L in default cause. use existing ccache
        if ((retval = krb5_cc_default(context, &ccache))) {
            mylog(LOG_ERR, "can't get your Kerberos credentials %s", error_message(retval));
            exit(1);
        }

        if ((retval = krb5_cc_get_principal(context, ccache, &client))) {
            mylog(LOG_ERR, "can't get principal from your Kerberos credentials %s", error_message(retval));
            exit(1);
        }
    }

    // drop privs as soon as possible
    // we ignore all user input so it's not clear how you'd exploit this program, but still, be safe
#ifdef PAM    
    setregid(pwd->pw_gid, pwd->pw_gid);
    setreuid(pwd->pw_uid, pwd->pw_uid); 
#else
    setregid(getgid(), getgid());
    setreuid(getuid(), getuid());
#endif

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
        mylog(LOG_ERR, "error looking up host '%s' port '%s'/tcp: %s",
                serverhost, portstr, gai_strerror(aierr));
        exit(1);
    }
    if (ap == 0) {
        /* Should never happen.  */
        mylog(LOG_ERR,"error looking up host '%s' port '%s'/tcp: no addresses returned?",
                serverhost, portstr);
        exit(1);
    }

    //    if (argc > 3) {
    //        service = argv[3];
    //    }

    retval = krb5_sname_to_principal(context, serverhost, service,
                                     KRB5_NT_SRV_HST, &server);
    if (retval) {
        mylog(LOG_ERR, "Error while creating server name for host %s service %s %s", 
              serverhost, service, error_message(retval));
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
            mylog(LOG_ERR, "%s: socket: %s", mbuf, strerror(errno));
            continue;
        }
        if (connect(sock, ap->ai_addr, ap->ai_addrlen) < 0) {
            mylog(LOG_ERR, "%s: connect: %s", mbuf, strerror(errno));
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
        mylog(LOG_ERR, "connected %d", sock);

    cksum_data.data = serverhost;
    cksum_data.length = strlen(serverhost);


    //retval = krb5_cc_default(context, &ccdef);
    //if (retval) {
    //    mylog(LOG_ERRval, "while getting default ccache %s", error_message(retval));
    //    exit(1);
    //}

    //retval = krb5_cc_get_principal(context, ccdef, &client);
    //if (retval) {
    //    mylog(LOG_ERRval, "while getting client principal name %s", error_message(retval));
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
            mylog(LOG_ERR, "deleting temporary cache %s", error_message(retval2));
            exit(1);
        }
    }

    // operatoin. currently just get
    if ((written = write(sock, (char *)&op,
                         1)) < 0) {
        mylog(LOG_ERR, "write failed 1");
        exit(1);
    }        
    if (debug)
        mylog(LOG_DEBUG, "write %c %ld", op, written);

    // username
    xmitlen = htons(strlen(username));
    if ((written = write(sock, (char *)&xmitlen,
                        sizeof(xmitlen))) < 0) {
        mylog(LOG_ERR, "write failed 1");
        exit(1);
    }
    if (debug)
        mylog(LOG_DEBUG, "write %lu", written);
    if ((written = write(sock, (char *)username,
                                 strlen(username))) < 0) {
        mylog(LOG_ERR, "write failed 2");
        exit(1);
    }

    if (debug)
        mylog(LOG_DEBUG, "write %lu", written);

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
        mylog(LOG_ERR, "write failed 1");
        exit(1);
    }
    if (debug)
        mylog(LOG_DEBUG, "write %lu", sizeof(xmitlen));
    if ((written = write(sock, (char *)principal,
                                 strlen(principal))) < 0) {
        mylog(LOG_ERR, "write failed 2");
        exit(1);
    }

    if (debug)
        mylog(LOG_DEBUG, "write %lu", strlen(principal));

    xmitlen = htons(strlen(flags));
    if ((written = write(sock, (char *)&xmitlen,
                        sizeof(xmitlen))) < 0) {
        mylog(LOG_ERR, "write failed 1");
        exit(1);
    }
    if (debug)
        mylog(LOG_DEBUG, "write %lu", sizeof(xmitlen));
    if ((written = write(sock, (char *)flags,
                                 strlen(flags))) < 0) {
        mylog(LOG_ERR, "write failed 2");
        exit(1);
    }

    if (debug)
        mylog(LOG_DEBUG, "write %lu", strlen(hostname));

    xmitlen = htons(strlen(hostname));
    if ((written = write(sock, (char *)&xmitlen,
                        sizeof(xmitlen))) < 0) {
        mylog(LOG_ERR, "write failed 1");
        exit(1);
    }
    if (debug)
        mylog(LOG_DEBUG, "write %lu", sizeof(xmitlen));
    if ((written = write(sock, (char *)hostname,
                                 strlen(hostname))) < 0) {
        mylog(LOG_ERR, "write failed 2");
        exit(1);
    }

    if (debug)
        mylog(LOG_DEBUG, "write %lu", strlen(hostname));

    krb5_free_principal(context, server);       /* finished using it */
    krb5_free_principal(context, client);

    //    krb5_cc_close(context, ccdef);
    //    if (auth_context) krb5_auth_con_free(context, auth_context);

    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
        if (retval == KRB5KRB_AP_ERR_BADADDR)
            mylog(LOG_ERR, "The official error message is \"Incorrect net address\", but this is usuallly caused when you don't have valid kerberos credentials");
        else
            mylog(LOG_ERR, "while using sendauth %s", error_message(retval));
        exit(1);
    }

    if (retval == KRB5_SENDAUTH_REJECTED) {
        /* got an error */
        mylog(LOG_ERR, "sendauth rejected, error reply is:\n\t\"%*s\"",
               err_ret->text.length, err_ret->text.data);
    } else if (rep_ret) {
        int isError = 0;
        char status[1];

        /* got a reply */
        krb5_free_ap_rep_enc_part(context, rep_ret);

        if (debug)
            mylog(LOG_DEBUG, "sendauth succeeded, reply is:");
        if ((retval = net_read(sock, (char *)status, 1)) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            mylog(LOG_ERR, "while reading data from server %s", error_message(retval));
            exit(1);
        }
        if (status[0] == 'e')
            isError = 1;

        if ((retval = net_read(sock, (char *)&xmitlen,
                               sizeof(xmitlen))) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            mylog(LOG_ERR, "while reading data from server %s", error_message(retval));
            exit(1);
        }
        recv_data.length = ntohs(xmitlen);
        if (!(recv_data.data = (char *)malloc((size_t) recv_data.length + 1))) {
            mylog(LOG_ERR, "No memory while allocating buffer to read from server");
            exit(1);
        }
        if ((retval = net_read(sock, (char *)recv_data.data,
                               recv_data.length)) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            mylog(LOG_ERR, "error while reading data from server");
            exit(1);
        }

        recv_data.data[recv_data.length] = '\0';

        if (isError) {
            // need username to help reading syslog messages
            mylog(LOG_ERR, "Error for %s: %s", pwd->pw_name, recv_data.data);
            exit(1);
        }

        if (op == 'G') {
            // replay protection doens't make sense for a client, and I don't want to set up a cache
            krb5_auth_con_setflags(context, auth_context, 0);

            retval = krb5_rd_cred(context, auth_context, &recv_data, &creds, &replay);
            if (retval) {
                mylog(LOG_ERR, "unable to read returned credentials %s", error_message(retval));
                exit(1);
            }

            if (krb5ccname) {
                if ((retval = krb5_cc_resolve(context, krb5ccname, &ccache))) {
                    mylog(LOG_ERR, "unable to get credentials cache %s %s", krb5ccname, error_message(retval));
                    exit(1);
                }
            } else {
                if ((retval = krb5_cc_default(context, &ccache))) {
                    mylog(LOG_ERR, "unable to get default credentials cache %s", error_message(retval));
                    exit(1);
                }
            }

            if (krb5_cc_get_principal(context, ccache, &defcache_princ)) {
                // cache not set up
                retval = krb5_cc_initialize(context, ccache, creds[0]->client);
                if (retval) {
                    mylog(LOG_ERR, "unable to initialize credentials file 1 %s", error_message(retval));
                    exit(1);
                }
            } else if (strcmp(krb5_cc_get_type(context, ccache), "FILE") == 0) {
                // cc exists; in KEYRING we can just store, but in /tmp create a new one and rename it
                // have to copy names, because cc_get_name is invalid after close
                // fortunately FILE: is the default, so we can just use the name for cc_resolv
                strncpy(realname, krb5_cc_get_name(context, ccache), sizeof(realname));
                snprintf(tempname, sizeof(tempname) - 1, "%s.%lu", realname, (unsigned long) getpid());

                krb5_cc_close(context, ccache);
                ccache = NULL;

                retval = krb5_cc_resolve(context, tempname, &ccache);
                if (retval) {
                    mylog(LOG_ERR, "unable to initialize credentials file %s %s", tempname, error_message(retval));
                    exit(1);
                }

                retval = krb5_cc_initialize(context, ccache, creds[0]->client);
                if (retval) {
                    mylog(LOG_ERR, "unable to initialize credentials file 2 %s", error_message(retval));
                    exit(1);
                }
                needrename = 1;
            }

            if ((retval = krb5_cc_store_cred(context, ccache, creds[0]))) {
                mylog(LOG_ERR, "unable to store credentials in cache %s", error_message(retval));
                exit(1);
            } 

            snprintf(realccname, sizeof(realccname), "%s:%s", 
                     krb5_cc_get_type(context, ccache),
                     (needrename ? realname : krb5_cc_get_name(context, ccache)));

#ifdef PAM
            printf("%s\n", realccname);
#else
            mylog(LOG_DEBUG, "%s", realccname);
#endif

            serial = add_key("user", "krbrenewd:ccname", realccname, strlen(realccname), KEY_SPEC_SESSION_KEYRING);
            if (serial == -1) {
                mylog(LOG_ERR, "kgetcred can't register credential file");
            }

            // others must be able to view and read, for renewd to see it
            if (keyctl_setperm(serial, 0x3f000003)) {
                mylog(LOG_ERR, "kgetcred can't set permissions for credential file");
            }

            krb5_cc_close(context, ccache);
            krb5_free_tgt_creds(context, creds);

            if (needrename) {
                if (rename(tempname, realname)) {
                    mylog(LOG_ERR, "Can't rename %s to %s %m", tempname, realname);
                }

            }
            

        } else {
            // list -- just print the data
            mylog(LOG_DEBUG, "%s", recv_data.data);
        }

        free(recv_data.data);
    } else {
        mylog(LOG_ERR, "no error or reply from sendauth!");
        exit(1);
    }
    // no attempt to free everything, since the program is about to exit
    freeaddrinfo(apstart);
    krb5_free_context(context);
    exit(0);
}


#ifdef PAM

#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {

  char ccput[1024];
  char *ccname = NULL;
  const char *username;
  struct passwd * pwd;
  pid_t child;
  int status;
  krb5_context context;
  int retval;
  char *specified_name = NULL; // ccache name specified by user
  char *default_realm = NULL;
  krb5_data realm_data;
  int pipefd[2];
  char *cp3;
  fd_set readset;
  struct timeval timeout;

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
      mylog(LOG_ERR, "pam_kgetcred unable to determine username");
      return PAM_SUCCESS; // go ahead and do the login anyway
  }

  pwd = getpwnam(username);
  if (!pwd) {
      mylog(LOG_ERR, "pam_kgetcred can't get information on current user");
      return PAM_SUCCESS; // go ahead and do the login anyway
  }

  if (pwd->pw_uid == 0)
      return PAM_SUCCESS; // we can't do anything for root

  // need context to get appdefault value. generating it isn't cheap
  // so pass it to the real proc and free it after return
  retval = krb5_init_context(&context);
  if (retval) {
      mylog(LOG_ERR, "while initializing krb5 %s", error_message(retval));
      return PAM_SUCCESS; // we can't do anything for root      
  }
  
  if ((retval = krb5_get_default_realm(context, &default_realm))) {
      mylog(LOG_ERR, "unable to get default realm %s", error_message(retval));
      krb5_free_context(context);
      return PAM_SUCCESS; // we can't do anything for root      
  }

  realm_data.data = default_realm;
  realm_data.length = strlen(default_realm);

  krb5_appdefault_string(context, "kgetcred", &realm_data, "ccname", "", &specified_name);
  
  krb5_free_default_realm(context, default_realm);

  // OK, have user-specified ccname in specified_name, if there was one
  // if specified name, replace %{uid} and use mkstemp for XXXXXX if they are there

  if (strcmp("", specified_name) != 0) {
      int fd;
      char *cp;

      snprintf(ccput, sizeof(ccput)-1, "KRB5CCNAME=%s", specified_name);
      ccname = ccput + strlen("KRB5CCNAME=");
      // if name starts with FILE:, skip it to get real file name
      if (strncmp(ccname, "FILE:", 5) == 0)
          ccname += 5;

      // if %{uid} replace it in ccput buffer, but not specified_name
      cp = strstr(ccname, "%{uid}");
      if (cp) {
          // find string in original. Has to be there since it's in the copy
          char *cp2 = strstr(specified_name, "%{uid}");
          snprintf(cp, sizeof(ccput) - (cp - ccput), "%lu", (unsigned long)pwd->pw_uid);
          strncat(cp, cp2 + 6, sizeof(ccput) - (cp-ccput));
      }

      // if it's a temp file with XXXXXX, use mkstemp. It will alter its caller, so
      // ccname will be updated
      if (strncmp(ccname, "/", 1) == 0 && // temp file
          strstr(ccname, "XXXXXX")) { // user asked for randomization
          fd = mkstemp(ccname); // will replace the XXXXXX in the buffer
          if (fd < 0) {
              mylog(LOG_ERR, "unable to create temp file %s", ccname);
              krb5_free_context(context);
              return PAM_SUCCESS; // we can't do anything for root      
          }
          fchmod(fd, 0700);
          fchown(fd, pwd->pw_uid, pwd->pw_gid);
          close(fd);
      }
  }

  // at this point if user specified a name ccname is set and replacements have been done
  // ccname will be the file name, ccput the VAR=VALUE appropriate for putenv

  if (pipe(pipefd)) {
      mylog(LOG_ERR, "pipe failed %m");
      krb5_free_context(context);
      return PAM_SUCCESS; // we can't do anything for root      
  }

  child = fork();
      
  if (child == 0) {
      // in child
      close(pipefd[0]); // close read side
      // make the pipe stdout
      if (dup2(pipefd[1], 1) < 0) { 
          mylog(LOG_ERR, "dup2 in child failed %m");
          exit(1);
      }
      close(pipefd[1]);

      // have to pass this globally to avoid changing all syslog calls to having this as arg
      pam_handle = pamh;

      pam_kgetcred(ccname, pwd, context);
      // return value will come from exit status
      mylog(LOG_ERR, "fork failed");
      krb5_free_context(context);  
      return PAM_SUCCESS; // go ahead and do the login anyway
  }
      
  close(pipefd[1]); // close write side

  // in parent
  waitpid(child, &status, 0);

  krb5_free_context(context);  

  if (WEXITSTATUS(status)) {
      // error should already have been logged
      return PAM_SUCCESS; // go ahead and do the login anyway      
  }

  strcpy(ccput, "KRB5CCNAME=");
  cp3 = ccput+strlen("KRB5CCNAME=");

  // read output from fork.
  // use select so we don't wait forever
  FD_ZERO(&readset);
  FD_SET(pipefd[0], &readset);
  timeout.tv_sec = 5;
  timeout.tv_usec = 0;

  while (select(pipefd[0]+1, &readset, NULL, NULL, &timeout) == 1) {
      read(pipefd[0], cp3, 1);
      if (*cp3 == '\n' || (cp3 - ccput) > (int)(sizeof(ccput) - 2))
          break;
      cp3++;
      FD_SET(pipefd[0], &readset);
  }

  if (*cp3 != '\n') {
      mylog(LOG_ERR, "read from fork failed %m");
  }      
  *cp3 = '\0';

  close(pipefd[0]); // close read side

  pam_putenv(pamh, ccput);

  return PAM_SUCCESS;

}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
} 

#endif

