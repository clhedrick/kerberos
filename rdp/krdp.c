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
 * krdp, the clientside of krdp/credserv. See the man page
 * for specifics of function.
 */


/* portability notes:

krdp uses setjmp/longjmp. Gcc/Intel/Linux has support in GCC to make it safe
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
#include <setjmp.h>
#include <signal.h>
#include <security/pam_ext.h>

#define SAMPLE_VERSION "KRB5_sample_protocol_v1.0"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>

#ifndef GETSOCKNAME_ARG3_TYPE
#define GETSOCKNAME_ARG3_TYPE int
#endif

#ifndef PAM
#ifdef MAC
extern char** environ;
#endif
#endif

char **getsrv( const char * domain,
               const char * service, const char * protocol );

static int
net_read(int fd, char *buf, int len)
{
    int cc, len2 = 0;

    __asm__ (".symver memcpy,memcpy@GLIBC_2.2.5");

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
 The program is setuid, so we have to think about security. The other end needs to be able to believe who we are.
 That's why we use host/foo.cs.rutgers.edu as our principal. It lets the other end verify tht we have access
 to the keytab, which should mean we're root, and they will check to make sure we're actualy coming from that IP.
 
 This program sends several parameters to the other end. However they are all checked on the server side
 to make sure they are permissible.

 The same source also produces a PAM module. That isn't setuid, but does run as root.

*/

// this is stupid. There are two different versions of strerror_r with the same name
// have to figure out which one we have and provide a standard interface
char *my_strerror(int errnum, char *buf, size_t buflen);
char *my_strerror(int errnum, char *buf, size_t buflen) {
#if (_POSIX_C_SOURCE >= 200112L) && !_GNU_SOURCE
    if (strerror_r(errnum, buf, buflen) == 0)
        return "unable to translate error number";
    return buf;
#else
    return strerror_r(errnum, buf, buflen);
#endif
}


#ifdef PAM
char *pam_krdp(const char *username, const char *uuid, struct passwd * pwd, krb5_context context, pam_handle_t *pamh);

char *pam_krdp(const char *username, const char *uuid, struct passwd * pwd, krb5_context context, pam_handle_t *pamh)
{
#else
int main(int argc, char *argv[])
{
    char *krb5ccname = NULL;
    int ch;
    struct passwd * pwd = NULL;
    krb5_context context = NULL;
    char *username = NULL;
    const char *uuid = NULL;
    struct passwd pwd_struct;
    char pwd_buf[2048];

#endif

    struct addrinfo *ap = NULL, aihints, *apstart = NULL;
    int aierr;
    int sock = -1;
    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval, retval2;
    krb5_ccache ccache = NULL;
    krb5_principal client = NULL, server = NULL;
    krb5_error *err_ret = NULL;
    krb5_ap_rep_enc_part *rep_ret = NULL;
    krb5_auth_context auth_context = 0;
    short xmitlen;
    char *portstr;
    char *service = "host";
    krb5_creds ** creds = NULL;
    krb5_replay_data replay;
    char realhost[1024];
    char *hostname = NULL;
    char *principal = NULL;
    const char *realccname;
    char *realcccopy = NULL;
    krb5_keytab hostkeytab = NULL;
    krb5_creds hostcreds;
    int havecreds = 0;
    long written;
    char *serverhost = "";
     char *default_realm = NULL;
     unsigned debug = 0;
     krb5_data realm_data;
     unsigned int waitsec = 30;
     krb5_get_init_creds_opt *opts = NULL;
     sigjmp_buf env;
     struct addrinfo hints;
     struct addrinfo * addrs;
     int userswitched = 0;
     uid_t olduid;
     gid_t oldgid;
     uid_t oldeuid;
     gid_t oldegid;
     char error_buf[2048];

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

     int write_item(int sockfd, const char *item, short itemlen, int oldret) {
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
     openlog("krdp", 0, LOG_AUTHPRIV);
     while ((ch = getopt(argc, argv, "dalruPU:F:H:w:")) != -1) {
         switch (ch) {
         case 'd':
             debug++;
             break;
         default:
             // debug because we don't want this going to syslog
             mylog(LOG_DEBUG, "-d debug username uuid");
             goto done;
             break;
         }
     }

     argc -= optind;
     argv += optind;

     if (argc > 1) {
         username = argv[0];
         uuid = argv[1];
     } else {
         mylog(LOG_DEBUG, "missing argument, expecting username uuid");
         goto done;
     }


     // This is the one environment varible we need.
     // So save it before cleaning environment, then
     // put it back
     krb5ccname = NULL;
#ifdef MAC
     environ = malloc(sizeof(char *));
     environ[0] = NULL;
#else
     clearenv();
#endif

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

    // get configuration info from krb5.conf. Both krdp and
    // pam_krdp use the same configuration section.

    realm_data.data = default_realm;
    realm_data.length = strlen(default_realm);

    krb5_appdefault_string(context, "krdp", &realm_data, "server", "", &serverhost);

    // address of credserv server
    if (strlen(serverhost) == 0) {
        mylog(LOG_ERR, "Please define server in the [appdefaults] section, e.g. \nkrdp = {\n     server=hostname\n}");
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

    olduid = getuid();
    oldgid = getgid();
    oldeuid = geteuid();
    oldegid = getegid();

    // use host credentials, from /etc/krb5.keytab

    // FQ hostname is now host->h_name
    
    if ((retval = krb5_build_principal(context, &client, strlen(default_realm), default_realm, "host", realhost, NULL))) {
        mylog(LOG_ERR,"unable to make principal for this host %s", error_message(retval));
        goto done;
    }

#ifndef PAM
    getpwnam_r(username, &pwd_struct, pwd_buf, sizeof(pwd_buf), &pwd);
    if (!pwd) {
        mylog(LOG_ERR, "pam_krdp can't get information on current user");
        goto done; // go ahead and do the login anyway
    }
#endif

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

    // so we don't have to do wait for the subprocess
    (void) signal(SIGPIPE, SIG_IGN);

    //if (argc > 2)
    //        portstr = argv[2];
    //    else
    portstr = "756";

    // get a connection to the server
    // if more than one, iterate down list

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
            mylog(LOG_ERR, "%s: socket: %s", mbuf, my_strerror(errno, error_buf, sizeof(error_buf)));
            continue;
        }
        if (connect(sock, ap->ai_addr, ap->ai_addrlen) < 0) {
            mylog(LOG_ERR, "%s: connect: %s", mbuf, my_strerror(errno, error_buf, sizeof(error_buf)));
            close(sock);
            sock = -1;
            continue;
        }
        if (debug)
            mylog(LOG_DEBUG, "%s: connected", mbuf);

        /* connected, yay! */
    }

    // tried all servers
    if (sock < 0) {
        mylog(LOG_ERR, "unable to connect to server");
        goto done;
    }

    if (debug)
        mylog(LOG_DEBUG, "connected %d", sock);

 // at this point ccache has credentials to be used
 // for connection, and client has the principal for them.

    cksum_data.data = serverhost;
    cksum_data.length = strlen(serverhost);

    // have the socket, ask Kerberos to make a secure connection

    if (debug) {
        char *printname, *printname2;
        if (krb5_unparse_name(context, server, &printname) == 0 && krb5_unparse_name(context, client, &printname2) == 0) {
            mylog(LOG_DEBUG, "about to do sendauth from %s to %s", printname2, printname);
            krb5_free_unparsed_name(context, printname);
            krb5_free_unparsed_name(context, printname2);
        }
    }

    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &sock,
                           SAMPLE_VERSION, client, server,
                           AP_OPTS_MUTUAL_REQUIRED,
                           &cksum_data,
                           NULL,
                           ccache, &err_ret, &rep_ret, NULL);

    if (debug && retval) {
        mylog(LOG_DEBUG, "sendauth failed");
    }

    // for G operation, we are going to need to generate credentials
    // from data that's returned. Destroy and deallocate the temporary
    // cache to avoid memory leak when we reuse ccache below.

    retval2 = krb5_cc_destroy(context, ccache);
    if (retval2) {
        mylog(LOG_ERR, "deleting temporary cache %s", error_message(retval2));
        goto done;
    }
    ccache = NULL;

    if (sigsetjmp(env, 1)) {
        mylog(LOG_ERR, "krdp timeout talking to server");
        goto done;
    }

    // set timeout. We're about to do network I/O
    signal (SIGALRM, catch_alarm);
    alarm(waitsec);  // this should be enough. we don't want to hang web processes that depend upon this too long

    // send the parameters to the server

    if (retval == 0) {
        written = write_item(sock, username, strlen(username), 0);
        written = write_item(sock, uuid, strlen(uuid), written);
    }

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
            mylog(LOG_ERR, "Error for %s: %s", username, recv_data.data);
            goto done;
        }

        alarm(0); // back to kerberos timeouts

        // if it's Kerberos credentials, set them up for the user

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

        setresgid(pwd->pw_gid, pwd->pw_gid, -1);
        setresuid(pwd->pw_uid, pwd->pw_uid, -1);
        userswitched = 1;

        // use default ccname
        if ((retval = krb5_cc_default(context, &ccache))) {
            mylog(LOG_ERR, "unable to get default credentials cache %s", error_message(retval));
            goto done;
        }

        // realccname should be just KCM: or KEYRING:persistent:nnn, not the actual cache
        realccname = krb5_cc_default_name(context);
        // need to copy it, because we'll deallocate the space inside context where this is stored
        if (realccname) {
            realcccopy = malloc(strlen(realccname) + 1);
            strcpy(realcccopy, realccname);
        }

        // have to initialize all the time, or we get duplicate entries
        // kinit does this even for kinit -R
        retval = krb5_cc_initialize(context, ccache, creds[0]->client);
        if (retval) {
            mylog(LOG_ERR, "unable to initialize credentials file 1 %s", error_message(retval));
            goto done;
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

        // close it before we do rename and chown
        krb5_cc_close(context,ccache);
        ccache = NULL;

        setresgid(oldgid, oldegid, -1);
        setresuid(olduid, oldeuid, -1);
        userswitched = 0;

        // final return is the name of the final cache
#ifndef PAM
            // have to do syslog directly because we don't want to print this to terminal.
        syslog(LOG_INFO, "User %s created credentials for %s in %s", username, principal, realccname);
#endif

#ifdef PAM            
        mylog(LOG_INFO, "User %s created credentials for %s in %s", username, principal, realccname);
#endif 

    } else {
        mylog(LOG_ERR, "no error or reply from sendauth!");
        goto done;
    }

    // if we got here, we're ok
    // mainret is st

 done:

    // if we got here from an error, might not have cancelled 
    // an alarm.
    alarm(0);

    if (userswitched) {
        setresgid(oldgid, oldegid, -1);
        setresuid(olduid, oldeuid, -1);
    }
    if (sock >= 0)
        close(sock);
    if (creds)
        krb5_free_tgt_creds(context, creds);
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
    return realcccopy;

#else
    if (realcccopy) {
        free(realcccopy);
        exit(0);
    } else
        exit(1);
#endif
}


#ifdef PAM

#include <security/pam_appl.h>
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {

  char ccput[1024];
  const char *username = "";
  char *password;
  struct passwd * pwd;
  struct passwd pwd_struct;
  char pwd_buf[2048];
  krb5_context context;
  int retval;
  char *mainret = NULL;


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
      mylog(LOG_ERR, "pam_krdp unable to determine username");
      return PAM_AUTHINFO_UNAVAIL; // go ahead and do the login anyway
  }

  if (pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password) != PAM_SUCCESS) {
      mylog(LOG_ERR, "pam_krdp unable to determine password");
      return PAM_AUTHINFO_UNAVAIL; // go ahead and do the login anyway
  }

  if (password == NULL) {
      pam_prompt(pamh, PAM_PROMPT_ECHO_OFF,
                 &password, "%s", "Password: ");
  }
  if (password == NULL) {
      mylog(LOG_ERR, "no password typed");
      return PAM_AUTHINFO_UNAVAIL; // go ahead and do the login anyway
  }      

  // no error message because this is normal if it's not from Guacamole
  if (strncmp(password,"##GUAC#", 7) != 0)
      return PAM_AUTHINFO_UNAVAIL; // go ahead and do the login anyway

  // skip past ##GUAC# to the uuid
  password = password + 7;

  getpwnam_r(username, &pwd_struct, pwd_buf, sizeof(pwd_buf), &pwd);
  if (!pwd) {
      mylog(LOG_ERR, "pam_krdp can't get information on current user");
      return PAM_USER_UNKNOWN; // go ahead and do the login anyway
  }

  if (pwd->pw_uid == 0)
      return PAM_USER_UNKNOWN; // we can't do anything for root, 

  // need context to get appdefault value. generating it isn't cheap
  // so pass it to the real proc and free it after return
  // context is free in function
  retval = krb5_init_context(&context);
  if (retval) {
      mylog(LOG_ERR, "while initializing krb5 %s", error_message(retval));
      return PAM_SERVICE_ERR;
  }
  
  // pam_krdp does setresuid and gid to user in pwd
  // we need to get back to root, or the rest of pam gets confused
  // pam_krdp frees context
  if ((mainret = pam_krdp(username, password, pwd, context, pamh)) == NULL) {
      mylog(LOG_ERR, "login failed");
      return PAM_AUTH_ERR; // go ahead and do the login anyway      
  }
  mylog(LOG_ERR, "login authorized by Guacamole user %s ccname %s", username, mainret);

  // got a ccname in mainret

  snprintf(ccput, sizeof(ccput)-1, "KRB5CCNAME=%s", mainret);

  pam_putenv(pamh, ccput);

  pam_set_data(pamh, "krdp_test", (void *)"true", NULL);

  free(mainret);

  return PAM_SUCCESS;

}

 PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
     return PAM_SUCCESS;
 }

#endif

