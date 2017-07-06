/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/* 
 * This code is based on the Kerberos sample client, which contains the 
 * license below. There is, however, virtually none of the original 
 * code left here without rewriting.
 *
 * The current code is Copyright 2017, by Rutgers, the State University of
 * New Jersey. It is released under the same license as MIT's, with the obvious
 * replacement of MIT by Rutgers.
 */

/* 
 * kgetcred, the clientside of kgetcred/credserv. See the man page
 * for specifics of function.
 */


/* portability notes:

kgetcred uses setjmp/longjmp. Gcc/Intel/Linux has support in GCC to make it safe
  For other architectures you may need special declarations to save all registers before
  the call to setjmp
There is a subtle portability issue in setresuid. This is used only in pam. We have to set
  real uid, or temp files and keys get created with root as owner. But we can't set saved
  uid, or we lose the ability to get back. It's not entirely clear what to do on systems
  without setresuid. It depends upon the specific semantics of setruid and setuid. In the 
  worst case you may have to create things as root and change ownership. But that opens
  possible race conditions.
If you don't have clearenv you'll need to use the MAC code

*/

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

#include "port-sockets.h"
#include "krb5.h"
#include "com_err.h"

#include <stdio.h>
#include <fcntl.h>
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
#include <setjmp.h>
#include <signal.h>
#include <security/pam_ext.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>

#include "sample.h"

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE int
#endif

#ifndef PAM
#ifdef MAC
extern char** environ;
#endif
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

int read_lasthost(char *buf, size_t bufsize);
int read_lasthost(char *buf, size_t bufsize) {
    int fd;
    size_t r;
    struct stat statbuf;

    fd = open("/tmp/kgetcred.last", O_RDONLY);
    if (fd == -1)
        return 1;
    // only read it if created by root. Normal users
    // can create files on /tmp. I think it's bad practice
    // to let a user point us to a host of their choice,
    // although mutual authentication should fail in the end
    if (fstat(fd, &statbuf) != 0) {
        close(fd);
        return 1;
    }
    if (statbuf.st_uid != 0) {
        close(fd);
        unlink("/tmp/kgetcred.last");
        return 1;
    }
    r = read(fd, buf, bufsize-1);
    close(fd);
    if (r == 0)
        return 1;
    if (r < bufsize)
        buf[r] = '\0';
    return 0;
}

int write_lasthost(char *buf);
int write_lasthost(char *buf) {
    int fd;
    size_t r;
    fd = open("/tmp/kgetcred.last", O_WRONLY|O_CREAT, 0644);
    if (fd == -1) {
        printf("fail 1 %m\n");
        return 1;
    }
    r = write(fd, buf, strlen(buf));
    close(fd);
    if (r == 0) {
        printf("fail 2\n");
        return 1;
    }
    return 0;
}


/*
 The program is setuid, so we have to think about security. The other end needs to be able to believe who we are.
 That's why we use host/foo.cs.rutgers.edu as our principal. It lets the other end verify tht we have access
 to the keytab, which should mean we're root, and they will check to make sure we're actualy coming from that IP.
 
 This program sends several parameters to the other end. However they are all checked on the server side
 to make sure they are permissible.

 The same source also produces a PAM module. That isn't setuid, but does run as root.

*/


#ifdef PAM
char *pam_kgetcred(char *krb5ccname, struct passwd * pwd, krb5_context context, pam_handle_t *pamh);

char *pam_kgetcred(char *krb5ccname, struct passwd * pwd, krb5_context context, pam_handle_t *pamh)
{
    key_serial_t serial;
#else
int main(int argc, char *argv[])
{
    char *krb5ccname = NULL;
    int ch;
    struct passwd * pwd = NULL;
    krb5_context context = NULL;
#endif

    struct addrinfo *ap = NULL, aihints, *apstart = NULL;
    int aierr;
    int sock = -1;
    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval, retval2;
    //krb5_ccache ccdef;
    krb5_ccache ccache = NULL;
    krb5_principal client = NULL, server = NULL, defcache_princ = NULL;
    krb5_error *err_ret = NULL;
    krb5_ap_rep_enc_part *rep_ret = NULL;
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
    krb5_keytab hostkeytab = NULL;
    krb5_creds hostcreds;
    int havecreds = 0;
    char *username = NULL;
    long written;
    char *serverhost = NULL;
    char *serverhostlist = NULL;
    char lasthost[1024];
    int lasthostdone = 0;
    int lasthostused = 0;
     char *default_realm = NULL;
     unsigned debug = 0;
     int anonymous = 0;
     char *clientname = NULL;
     int prived = 0;
     char *flags = "";
     krb5_data realm_data;
     unsigned int cwaitsec = 15; // connect wait
     unsigned int waitsec = 30;
     krb5_get_init_creds_opt *opts = NULL;
     krb5_creds usercreds;
     int haveusercreds = 0;
     char * mainret = NULL;
     sigjmp_buf env;
     struct addrinfo hints;
     struct addrinfo * addrs;

     // this has to be internal, because it needs pamh, which is a local
     void __attribute__ ((format (printf, 2, 3))) mylog (int level, const char *format, ...) {
#ifndef PAM
         char *message;
#endif
         va_list args;
         va_start (args, format);
#ifdef PAM
         pam_vsyslog(pamh, level, format, args);
#else
         // it's really hard to use the arg list twice
         // safer to print to a malloced string
         if (vasprintf(&message, format, args) >= 0) {
             printf("%s\n", message);
             if (level != LOG_DEBUG)
                 syslog(level, "%s", message);
             free(message);
         }
#endif
         va_end(args);
     }

     int write_item(int sockfd, char *item, short itemlen, int oldret) {
         short xmitsize;
         int wrote;
         
         // if already have an error, don't do any more
         if (oldret < 0)
             return oldret;
         
         xmitsize = htons(itemlen);
         if ((wrote = write(sockfd, (char *)&xmitsize,
                              sizeof(xmitsize))) < 0) {
             mylog(LOG_ERR, "write failed length");
             return 1;
         }
         if (debug)
             mylog(LOG_DEBUG, "write %u", wrote);
         
         if ((wrote = write(sockfd, item, itemlen)) < 0) {
             mylog(LOG_ERR, "write failed item");
             return 1;
         }
         if (debug)
             mylog(LOG_DEBUG, "write %u", wrote);
         
         return wrote;
     }

     // Timeout for network I/O
     // NOTE: we only alarm network I/O that we do. We don't alarm any kerberos
     // library functions. We assume that Kerberos does its own timeouts. If we
     // longjmp out of a Kerberos library, it is very likely that they will have 
     // allocated data structures, and we'll have a memory leak.
     void catch_alarm (int sig) {
         siglongjmp(env, 1);
     }


     recv_data.data = NULL;
     memset(&hints, 0, sizeof(hints));
     hints.ai_family = AF_UNSPEC;
     hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;

     /*
      * Parse command line arguments
      *
      */
     opterr = 0;
#ifndef PAM
     // pam uses pam_syslog, which doesn't need this
     openlog("kgetcred", 0, LOG_AUTHPRIV);
     while ((ch = getopt(argc, argv, "dalruPU:F:H:w:")) != -1) {
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
         case 'w':
             waitsec = atoi(optarg);
             cwaitsec = atoi(optarg);
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
             // debug because we don't want this going to syslog
             mylog(LOG_DEBUG, "-d debug, -a get anonymous ticket, -l list, -r register, -u unregister -w waittime; -P prived user, -U user to operate on, -F flags, -H hostname for entry");
             goto done;
             break;
         }
     }

     argc -= optind;
     argv += optind;

     if (argc > 0)
         principal = argv[0];

     // This is the one environment varible we need.
     // So save it before cleaning environment, then
     // put it back
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
    // end of non-PAM   

    if (!context) {
        retval = krb5_init_context(&context);
        if (retval) {
            mylog(LOG_ERR, "while initializing krb5 %s", error_message(retval));
            goto done;
        }
    }

    if ((retval = krb5_get_default_realm(context, &default_realm))) {
        mylog(LOG_ERR, "unable to get default realm %s", error_message(retval));
        goto done;
    }

    // get configuration info from krb5.conf. Both kgetcred and
    // pam_kgetcred use the same configuration section.

    realm_data.data = default_realm;
    realm_data.length = strlen(default_realm);

    krb5_appdefault_string(context, "kgetcred", &realm_data, "server", "", &serverhostlist);

    // address of credserv server
    if (strlen(serverhostlist) == 0) {
        mylog(LOG_ERR, "Please define server in the [appdefaults] section, e.g. \nkgetcred = {\n     server=hostname\n}");
        goto done;
    }

    // our hostname
    realhost[sizeof(realhost)-1] = '\0';
    gethostname(realhost, sizeof(realhost)-1);
    retval = getaddrinfo(realhost, NULL, &hints, &addrs);
    if (retval || !addrs->ai_canonname) {
        mylog(LOG_ERR, "hostname %s not found", realhost);
        // use result of gethostname
    } else {
        strncpy(realhost, addrs->ai_canonname, sizeof(realhost)-1);
        freeaddrinfo(addrs);
    }
    
    // Realhost is our actual host
    // Hostname is the argument sent to the other end. For register
    //  and unregister it's the hostname to register (only allowed for
    //  admin users). Obviously hostname defaults to our real host
    if (hostname == NULL)
        hostname = realhost;

    // user we're running as. This will be sent to the other
    // end is the username to act on, though an admin user can
    // override it. pwd is also used to change our userid
    // back to the user when we've finished doing things that
    // require setuid root.
    if (!pwd) {
        pwd = getpwuid(getuid());
        if (!pwd) {
            mylog(LOG_ERR, "Can't find current user");
            goto done;
        }
    }

    // username user the action applies to, not necesarily the one we will authenticate as
    // defaults to current user.
    if (!username) {
        if (anonymous)
            username = "anonymous.user";
        else
            username = pwd->pw_name;
    }

    // op is which command we're doing.
    // G - get credentials for the current user.  For this
    // we don't have user credentials, so we have to use the host's.
    if (op == 'G') {
        // use host credentials, from /etc/krb5.keytab

        // FQ hostname is now host->h_name

        if ((retval = krb5_build_principal(context, &client, strlen(default_realm), default_realm, "host", realhost, NULL))) {
            mylog(LOG_ERR,"unable to make principal for this host %s", error_message(retval));
            goto done;
        }

        if ((retval = krb5_kt_resolve(context, "/etc/krb5.keytab", &hostkeytab))) {
            mylog(LOG_ERR, "unable to get keytab for this host %s", error_message(retval));
            goto done;
        }

        if ((retval = krb5_get_init_creds_keytab(context, &hostcreds, client, hostkeytab, 0,  NULL, NULL))) {
            mylog(LOG_ERR, "unable to make credentials for host from keytab %s", error_message(retval));
            goto done;
        }
        havecreds = 1;

        // we have to make a credentials cache (remember we're using a keytab, so
        // we don't have a credentias cache), for the call that sets up an
        // authenticated connection. Use a temporary member CC, because no one
        // else needs it.
        if ((retval = krb5_cc_new_unique(context, "MEMORY", "/tmp/jjjjj", &ccache))) {
            mylog(LOG_ERR, "unable to make credentials file for host %s", error_message(retval));
            goto done;
        }

        if ((retval = krb5_cc_initialize(context, ccache, client))) {
            mylog(LOG_ERR, "unable to initialized credentials file for host %s", error_message(retval));
            goto done;
        }                                                                                                                        

        if ((retval = krb5_cc_store_cred(context, ccache, &hostcreds))) {                                                                  mylog(LOG_ERR, "unable to store host credentials in cache %s", error_message(retval));
            goto done;
        }

    } else if (op != 'L' && !prived) {
        // for register and unregister if not privileged prompt for new
        // credentials. This is based in the -P option. Clearly an unprivileged
        // user can specify -P, but the other end will check that the credentials
        // were obtained in the last 30 sec, so it won't do them much good.
        //  The point of this is the this operation opens up your security.
        // We don't want root to be able to find credentials lying around from
        // a long-running job and use then to register the current host.

        if (!clientname)
            clientname = pwd->pw_name;

        if ((retval = krb5_build_principal(context, &client, strlen(default_realm), default_realm, clientname, NULL))) {
            mylog(LOG_ERR, "unable to make principal from your username %s", error_message(retval));
            goto done;
        }

        if ((retval = krb5_get_init_creds_opt_alloc(context, &opts))) {
            mylog(LOG_ERR, "unable to set up to get your password %s", error_message(retval));
            goto done;
        }

        krb5_get_init_creds_opt_set_tkt_life(opts, 60); // no need to keep them around for long
        krb5_get_init_creds_opt_set_renew_life(opts, 0);
        krb5_get_init_creds_opt_set_forwardable(opts, 0);
        krb5_get_init_creds_opt_set_proxiable(opts, 0);

        if ((retval = krb5_get_init_creds_password(context, &usercreds, client, NULL, krb5_prompter_posix, NULL,
                                                   0, NULL, opts))) {
            if (retval == KRB5KRB_AP_ERR_BAD_INTEGRITY)
                mylog(LOG_ERR, "Password incorrect -- note that if you are using a one-time password this utility can't work: %s", error_message(retval));
            else
                mylog(LOG_ERR, "Error getting initial ticket -- note that if you are using a one-time password this utility can't work: %s", error_message(retval));
            goto done;
        }
        haveusercreds = 1;

        // now have credentials for current user.
        // put them in a credentials cache for library call that makes
        // a secure connection.

        if ((retval = krb5_cc_new_unique(context, "MEMORY", "/tmp/kkkk", &ccache))) {
            mylog(LOG_ERR, "unable to make credentials file for host %s", error_message(retval));
            goto done;
        }

        if ((retval = krb5_cc_store_cred(context, ccache, &usercreds))) { 
            mylog(LOG_ERR, "unable to store your credentials in cache %s", error_message(retval));
            goto done;
        }

    } else {
        // For list command, and for register and unregister if a privileged user
        // Just use current default credentials
        if ((retval = krb5_cc_default(context, &ccache))) {
            mylog(LOG_ERR, "can't get your Kerberos credentials %s", error_message(retval));
            goto done;
        }

        if ((retval = krb5_cc_get_principal(context, ccache, &client))) {
            mylog(LOG_ERR, "can't get principal from your Kerberos credentials %s", error_message(retval));
            goto done;
        }
    }

    // so we don't have to do wait for the subprocess
    (void) signal(SIGPIPE, SIG_IGN);

    //if (argc > 2)
    //        portstr = argv[2];
    //    else
    portstr = "755";

    // get a connection to the server
    // if more than one, iterate down list
 while (1) {
    // first see if there's a saved host. This is one that worked
    // last time. This is to prevent having to time out every time
    // if the first host is down
    if (!lasthostdone && read_lasthost(lasthost, sizeof(lasthost)) == 0) {
        serverhost = lasthost;
        lasthostused = 1;
    }
    // done with saved host, get next host from list
    else if (!(serverhost = strsep(&serverhostlist, ",")))
        break;

    // skip blanks
    while(*serverhost == ' ')
        serverhost++;
    // if nothing left, e.g. trailing comma, done
    if (!*serverhost) {
        break;
    }

    // we don't want to try last host a second time
    // if we used lasthost, and this isn't the first try with it,
    // skip it
    if (lasthostdone && lasthostused && strcmp(lasthost, serverhost) == 0)
        continue;
    lasthostdone = 1;

    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_socktype = SOCK_STREAM;
    aihints.ai_flags = AI_ADDRCONFIG;
    aierr = getaddrinfo(serverhost, portstr, &aihints, &ap);
    if (aierr) {
        mylog(LOG_ERR, "error looking up host '%s' port '%s'/tcp: %s",
                serverhost, portstr, gai_strerror(aierr));
        goto done;
    }
    if (ap == 0) {
        /* Should never happen.  */
        mylog(LOG_ERR,"error looking up host '%s' port '%s'/tcp: no addresses returned?",
                serverhost, portstr);
        goto done;
    }

    //    if (argc > 3) {
    //        service = argv[3];
    //    }

    // principal for the server. needed by the library call to make
    // a secure connection

    retval = krb5_sname_to_principal(context, serverhost, service,
                                     KRB5_NT_SRV_HST, &server);
    if (retval) {
        mylog(LOG_ERR, "Error while creating server name for host %s service %s %s", 
              serverhost, service, error_message(retval));
        goto done;
    }

    // set timeout for opening the connection. If it fails, try next host
    if (sigsetjmp(env, 1)) {
        alarm(0);
        continue;
    }

    signal (SIGALRM, catch_alarm);
    alarm(cwaitsec);  // this should be enough. we don't want to hang web processes that depend upon this too long

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

    alarm(0);

    // connect failed. ran out of addresses for this host to try
    if (sock == -1)
        continue;

    // if we got here without an alarm, exit and use this host
    break;

  }  // end of loop over hosts

    // tried all servers
    if (serverhost == NULL || !*serverhost) {
        mylog(LOG_ERR, "unable to connect to server");
        goto done;
    }

    // kerberos will do its own timeouts, so remove the timeout

    if (sock == -1)
        /* Already printed error message above.  */
        goto done;
    if (debug)
        mylog(LOG_DEBUG, "connected %d", sock);
    // connect apparently worked. save it in lasthost
    // only save if new value is different
    if (!lasthostused || strcmp(lasthost, serverhost) != 0)
        write_lasthost(serverhost);

    // at this point ccache has credentials to be used
    // for connection, and client has the principal for them.

    // drop privs as soon as possible
    // there's not much user input so it's not clear how you'd exploit this program, but still, be safe
#ifdef PAM    
    // for PAM, have to leave saved uid as root, or we can't get back
    setresgid(pwd->pw_gid, pwd->pw_gid, -1);
    setresuid(pwd->pw_uid, pwd->pw_uid, -1);
#else
    // for non-pam, we don't have to get back, so drop irrevocably
    setegid(pwd->pw_gid);
    seteuid(pwd->pw_uid);
#endif

    cksum_data.data = serverhost;
    cksum_data.length = strlen(serverhost);

    // have the socket, ask Kerberos to make a secure connection

    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &sock,
                           SAMPLE_VERSION, client, server,
                           AP_OPTS_MUTUAL_REQUIRED,
                           &cksum_data,
                           NULL,
                           ccache, &err_ret, &rep_ret, NULL);

    // for G operation, we are going to need to generate credentials
    // from data that's returned. Destroy and deallocate the temporary
    // cache to avoid memory leak when we reuse ccache below.

    if (op == 'G') {
        retval2 = krb5_cc_destroy(context, ccache);
        if (retval2) {
            mylog(LOG_ERR, "deleting temporary cache %s", error_message(retval2));
            goto done;
        }
        ccache = NULL;
    }

    // probably should try next host, but I'm not sure this code is written to be done twice
    if (sigsetjmp(env, 1)) {
        mylog(LOG_ERR, "kgetcred timeout talking to server");
        goto done;
    }

    // set timeout. We're about to do network I/O
    signal (SIGALRM, catch_alarm);
    alarm(waitsec);  // this should be enough. we don't want to hang web processes that depend upon this too long

    // send the parameters to the server

    // operation code
    if ((written = write(sock, (char *)&op,
                         1)) < 0) {
        mylog(LOG_ERR, "write failed 1");
        goto done;
    }        
    if (debug)
        mylog(LOG_DEBUG, "write %c %ld", op, written);

    written = write_item(sock, username, strlen(username), 0);

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

    written = write_item(sock, principal, strlen(principal), written);
    written = write_item(sock, flags, strlen(flags), written);
    written = write_item(sock, hostname, strlen(hostname), written);

    if (written < 0)
        goto done;

    //    krb5_cc_close(context, ccdef);
    //    if (auth_context) krb5_auth_con_free(context, auth_context);


    // now process any errors from the sendauth.


    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
        if (retval == KRB5KRB_AP_ERR_BADADDR)
            mylog(LOG_ERR, "The official error message is \"Incorrect net address\", but this is usuallly caused when you don't have valid kerberos credentials");
        else
            mylog(LOG_ERR, "while using sendauth %s", error_message(retval));
        goto done;
    }

    if (retval == KRB5_SENDAUTH_REJECTED) {
        /* got an error */
        mylog(LOG_ERR, "sendauth rejected, error reply is:\n\t\"%*s\"",
               err_ret->text.length, err_ret->text.data);
    } else if (rep_ret) {

        // if it worked, read the response and process it

        int isError = 0;
        char status[1];

        if (debug)
            mylog(LOG_DEBUG, "sendauth succeeded, reply is:");

        // response can be credentials, error, or output to print
        // the first byte indicates which

        if ((retval = net_read(sock, (char *)status, 1)) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            mylog(LOG_ERR, "while reading data from server %s", error_message(retval));
            goto done;
        }

        // error
        if (status[0] == 'e')
            isError = 1;

        // now read response
        if ((retval = net_read(sock, (char *)&xmitlen,
                               sizeof(xmitlen))) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            mylog(LOG_ERR, "while reading data from server %s", error_message(retval));
            goto done;
        }
        recv_data.length = ntohs(xmitlen);
        if (!(recv_data.data = (char *)malloc((size_t) recv_data.length + 1))) {
            mylog(LOG_ERR, "No memory while allocating buffer to read from server");
            goto done;
        }
        if ((retval = net_read(sock, (char *)recv_data.data,
                               recv_data.length)) <= 0) {
            if (retval == 0)
                errno = ECONNABORTED;
            mylog(LOG_ERR, "error while reading data from server");
            goto done;
        }

        recv_data.data[recv_data.length] = '\0';

        // process response

        // if it's an error, print it and exit

        if (isError) {
            // need username to help reading syslog messages
            mylog(LOG_ERR, "Error for %s: %s", pwd->pw_name, recv_data.data);
            goto done;
        }

        alarm(0); // back to kerberos timeouts

        // if it's Kerberos credentials, set them up for the user

        if (op == 'G') {

            // replay protection doens't make sense for a client, and I don't want to set up a cache
            krb5_auth_con_setflags(context, auth_context, 0);

            // reads the special KRB-CRED message that has credentials in it. The 
            // most sensitive part is encrypted with the session key
            retval = krb5_rd_cred(context, auth_context, &recv_data, &creds, &replay);
            if (retval) {
                mylog(LOG_ERR, "unable to read returned credentials %s", error_message(retval));
                goto done;
            }

            // we're about to reuse the cache
            if (ccache) {
                // in case it was used above
                krb5_cc_close(context,ccache);
                ccache = NULL;
            }

            // krb5ccname is set if user has asked for a specific
            // cache, either from environment variable or PAM
            // configuration.

            if (krb5ccname) {
                // for specific cache, open it
                if ((retval = krb5_cc_resolve(context, krb5ccname, &ccache))) {
                    mylog(LOG_ERR, "unable to get credentials cache %s %s", krb5ccname, error_message(retval));
                    goto done;
                }
            } else {
                // otherwise use default
                if ((retval = krb5_cc_default(context, &ccache))) {
                    mylog(LOG_ERR, "unable to get default credentials cache %s", error_message(retval));
                    goto done;
                }
            }

            if (krb5_cc_get_principal(context, ccache, &defcache_princ) != 0 || 
                !krb5_principal_compare(context, creds[0]->client, defcache_princ)) {
                // cache not set up or wrong principal
                retval = krb5_cc_initialize(context, ccache, creds[0]->client);
                if (retval) {
                    mylog(LOG_ERR, "unable to initialize credentials file 1 %s", error_message(retval));
                    goto done;
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
                    goto done;
                }

                retval = krb5_cc_initialize(context, ccache, creds[0]->client);
                if (retval) {
                    mylog(LOG_ERR, "unable to initialize credentials file 2 %s", error_message(retval));
                    goto done;
                }
                needrename = 1;
            }

            // now we've got the cache open and initialized
            // store the credentials in it
            if ((retval = krb5_cc_store_cred(context, ccache, creds[0]))) {
                mylog(LOG_ERR, "unable to store credentials in cache %s", error_message(retval));
                goto done;
            } 

            // generate the name of the cache, for printing or
            // return to PAM. If the cache is a temporary which
            // will have to be renamed, use the real name, i.e.
            // the one it will end up as.
            snprintf(realccname, sizeof(realccname), "%s:%s", 
                     krb5_cc_get_type(context, ccache),
                     (needrename ? realname : krb5_cc_get_name(context, ccache)));

            // close it before we do rename and chown
            krb5_cc_close(context,ccache);
            ccache = NULL;

            // final return is the name of the final cache
            mainret = realccname;
#ifndef PAM
            mylog(LOG_DEBUG, "%s", realccname);
            // have to do syslog directly because we don't want to print this to terminal.
            syslog(LOG_INFO, "User %s created credentials for %s in %s", username, principal, realccname);
#endif

#ifdef PAM            
            mylog(LOG_INFO, "User %s created credentials for %s in %s", username, principal, realccname);
            // register this credential in the session keyring.
            // renewd uses this to check which credential caches are
            // still active and so need to be renewed
            serial = add_key("user", "krbrenewd:ccname", realccname, strlen(realccname), KEY_SPEC_SESSION_KEYRING);
            if (serial == -1) {
                mylog(LOG_ERR, "kgetcred can't register credential file");
            }

            // others must be able to view and read, for renewd to see it
            if (keyctl_setperm(serial, 0x3f000003)) {
                mylog(LOG_ERR, "kgetcred can't set permissions for credential file");
            }

#endif 


            // do the rename for files in /tmp, from temporary to real file name
            if (needrename) {
                if (rename(tempname, realname)) {
                    mylog(LOG_ERR, "Can't rename %s to %s %m", tempname, realname);
                }

            }

        } else {
            // data returned was output (tagged with 'l' because it's a listing)
            // just print it
            mylog(LOG_DEBUG, "%s", recv_data.data);
        }
    } else {
        mylog(LOG_ERR, "no error or reply from sendauth!");
        goto done;
    }

    // if we got here, we're ok
    // only 'G' op sets mainret, so need to flag things are OK for others
    if (!mainret)
        mainret = "ok";

 done:

    // if we got here from an error, might not have cancelled 
    // an alarm.
    alarm(0);
    if (sock >= 0)
        close(sock);
    if (creds)
        krb5_free_tgt_creds(context, creds);
    if (defcache_princ)
        krb5_free_principal(context, defcache_princ);
    if (recv_data.data)
        free(recv_data.data);
    if (rep_ret)
        krb5_free_ap_rep_enc_part(context, rep_ret);
    if (err_ret)
        krb5_free_error(context, err_ret);
    if (server)
        krb5_free_principal(context, server);
    if (apstart)
        freeaddrinfo(ap);
    else if (ap)
        freeaddrinfo(ap);
    if (haveusercreds)
        krb5_free_cred_contents(context, &usercreds);
    if (opts)
        krb5_get_init_creds_opt_free(context,opts);
    if (ccache)
        krb5_cc_close(context,ccache);
    if (havecreds)
        krb5_free_cred_contents(context, &hostcreds);
    if (hostkeytab)
        krb5_kt_close(context, hostkeytab);
    if (client)
        krb5_free_principal(context, client);
    if (default_realm)
        krb5_free_default_realm(context, default_realm);
    if (context)
        krb5_free_context(context);

#ifdef PAM
    // returned value is local buffer. need to malloc it for it to be valid on exit
    if (mainret) {
        char *retcopy = malloc(strlen(mainret) + 1);
        strcpy(retcopy, mainret);
        mainret = retcopy;
    }
    return mainret;
#else
    if (mainret)
        exit(0);
    else
        exit(1);
#endif
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
  krb5_context context;
  int retval;
  char *specified_name = NULL; // ccache name specified by user
  char *default_realm = NULL;
  krb5_data realm_data;
  char *mainret = NULL;
  uid_t olduid;
  gid_t oldgid;
  int i;

  // this has to be internal, because it needs pamh, which is a local
  void __attribute__ ((format (printf, 2, 3))) mylog (int level, const char *format, ...) {
      va_list args;
      va_start (args, format);
#ifdef PAM
      pam_vsyslog(pamh, level, format, args);
#else
      vprintf(format, args);
      printf("\n");
#endif
      va_end(args);
  }

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
      mylog(LOG_ERR, "pam_kgetcred unable to determine username");
      return PAM_AUTHINFO_UNAVAIL; // go ahead and do the login anyway
  }

  pwd = getpwnam(username);
  if (!pwd) {
      mylog(LOG_ERR, "pam_kgetcred can't get information on current user");
      return PAM_USER_UNKNOWN; // go ahead and do the login anyway
  }

  if (pwd->pw_uid == 0)
      return PAM_USER_UNKNOWN; // we can't do anything for root, 

  // need context to get appdefault value. generating it isn't cheap
  // so pass it to the real proc and free it after return
  retval = krb5_init_context(&context);
  if (retval) {
      mylog(LOG_ERR, "while initializing krb5 %s", error_message(retval));
      return PAM_SERVICE_ERR;
  }
  
  if ((retval = krb5_get_default_realm(context, &default_realm))) {
      mylog(LOG_ERR, "unable to get default realm %s", error_message(retval));
      krb5_free_context(context);
      return PAM_SERVICE_ERR; // we can't do anything for root      
  }

  realm_data.data = default_realm;
  realm_data.length = strlen(default_realm);

  krb5_appdefault_string(context, "kgetcred", &realm_data, "ccname", "", &specified_name);
  
  krb5_free_default_realm(context, default_realm);

  // OK, have user-specified ccname in specified_name, if there was one
  // if specified name, replace %{uid} and use mkstemp for XXXXXX if they are there

  if (strcmp("", specified_name) != 0) {
      int fd;
      char *cpin, *cpout, *cpend;
      char ch;

      strcpy(ccput, "KRB5CCNAME=");
      ccname = ccput + strlen("KRB5CCNAME=");

      cpin = specified_name;
      cpout = ccname;
      cpend = ccput + sizeof(ccput) - 1;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-overflow"
      while ((cpout < cpend) && (ch = *cpin)) {
#pragma GCC diagnostic pop
          if (ch == '%') {
              if (strncmp(cpin, "%{uid}", strlen("%{uid}")) == 0) {
                  int chars;
                  chars = snprintf(cpout, cpend - cpout, "%lu", (unsigned long)pwd->pw_uid);
                  if (chars < 0)
                      break;
                  cpout += chars;
                  cpin += strlen("%(uid}");
              } else if (strncmp(cpin, "%{username}", strlen("%{username}")) == 0) {
                  int chars;
                  chars = snprintf(cpout, cpend - cpout, "%s", pwd->pw_name);
                  if (chars < 0)
                      break;
                  cpout += chars;
                  cpin += strlen("%(username}");
              } else 
                  *cpout++ = *cpin++;
          } else
              *cpout++ = *cpin++;
      }
      // cpend is defined so there's always a place for the terminating NUL
      *cpout = '\0'; 

      // if name starts with FILE:, skip it to get real file name
      if (strncmp(ccname, "FILE:", 5) == 0)
          ccname += 5;

      // if it's a temp file with XXXXXX, use mkstemp. It will alter its caller, so
      // ccname will be updated
      if (strncmp(ccname, "/", 1) == 0 && // temp file
          strstr(ccname, "XXXXXX")) { // user asked for randomization
          fd = mkstemp(ccname); // will replace the XXXXXX in the buffer
          if (fd < 0) {
              mylog(LOG_ERR, "unable to create temp file %s", ccname);
              krb5_free_context(context);
              return PAM_SYSTEM_ERR; // we can't do anything for root      
          }
          fchmod(fd, 0700);
          fchown(fd, pwd->pw_uid, pwd->pw_gid);
          close(fd);
      }
  }

  olduid = getuid();
  oldgid = getgid();

  // pam_kgetcred does setresuid and gid to user in pwd
  // we need to get back to root, or the rest of pam gets confused
  // pam_kgetcred frees context
  if ((mainret = pam_kgetcred(ccname, pwd, context, pamh)) == NULL) {
      setresuid(olduid, olduid, -1);
      setresgid(oldgid, oldgid, -1);
      return PAM_CRED_UNAVAIL; // go ahead and do the login anyway      
  }
  setresuid(olduid, olduid, -1);
  setresgid(oldgid, oldgid, -1);

  // got a ccname in mainret
  // if we're supposed to use collection name, remove subsidiary

  // mainret is our malloced memory. It's OK for us to stick a null
  // in it.

  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "usecollection") == 0 &&
	strncmp(mainret, "KEYRING:", 8) == 0) {
      // count colons in ccname
      int numcolon = 0; 
      char *cp;
      for (cp = mainret; *cp; cp++) {
	if (*cp == ':')
	  numcolon++;
	if (numcolon == 3) {
            *cp = '\0';
            break;
        }
      }
    }
    break;
  }

  snprintf(ccput, sizeof(ccput)-1, "KRB5CCNAME=%s", mainret);

  pam_putenv(pamh, ccput);

  free(mainret);

  return PAM_SUCCESS;

}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
} 

#endif

