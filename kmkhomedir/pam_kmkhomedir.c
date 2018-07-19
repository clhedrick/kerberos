/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* appl/sample/sclient/sclient.c */
/*
 * Copyright 2017 by Rutgers, the State University of New Jersey
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
 * the name of Rutgers not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original Rutgers software.
 * Rutgers makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
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
#include <syslog.h>
#include <wait.h>
#include <pwd.h>
#include <sys/stat.h>

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
char *pam_kmkhomedir(char *dirname, struct passwd * pwd, char* serverhost);

char *pam_kmkhomedir(char *dirname, struct passwd * pwd, char* serverhost)
{
#else
int main(int argc, char *argv[])
{
    char ch;
    char *dirname = NULL;
    struct passwd * pwd;
    char *serverhost = NULL;
#endif

    struct addrinfo *ap, aihints, *apstart = NULL;
    int aierr;
    int sock = -1;
    krb5_context context = NULL;
    krb5_data realm_data;
    krb5_data recv_data;
    krb5_data cksum_data;
    krb5_error_code retval;
    //krb5_ccache ccdef;
    krb5_ccache ccache = NULL;
    krb5_principal client = NULL, server = NULL;
    krb5_error *err_ret;
    krb5_ap_rep_enc_part *rep_ret;
    krb5_auth_context auth_context = 0;
    short xmitlen;
    char *portstr;
    char *service = "mkhomedird";
    char realhost[1024];
    char *hostname = NULL;
    struct addrinfo hints;
    struct addrinfo * addrs;
    krb5_keytab hostkeytab = NULL;
    krb5_creds hostcreds;
    int have_cred = 0;
    char *username = NULL;
    long written;
    char *default_realm = NULL;
    unsigned debug = 0;
    char *message = NULL;
    char *testfile = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG | AI_CANONNAME;

     /*
      * Parse command line arguments
      *
      */
     opterr = 0;
#ifndef PAM
     while ((ch = getopt(argc, argv, "d")) != -1) {
         switch (ch) {
         case 'd':
             debug++;
             break;
         default:
             mylog(LOG_ERR, "[-d] username dirname [server]");
             exit(1);
             break;
         }
     }

     argc -= optind;
     argv += optind;

     if (argc < 2) {
         mylog(LOG_ERR, "[-d] username dirname [server]");
         exit(1);
     }

     username = argv[0];
     dirname = argv[1];
     if (argc > 2)
         serverhost = argv[2];

#else
    username = pwd->pw_name;
#endif

#ifdef MAC
    environ = malloc(sizeof(char *));
    environ[0] = NULL;
#else
    clearenv();
#endif

    recv_data.data = NULL;
    recv_data.length = 0;

    retval = krb5_init_context(&context);
    if (retval) {
        message = "krb5_init_context failed";
        goto done;
    }


    if ((retval = krb5_get_default_realm(context, &default_realm))) {
        message = "unable to get default realm";
        goto done;
    }

    realm_data.data = default_realm;
    realm_data.length = strlen(default_realm);

    if (!serverhost)
        krb5_appdefault_string(context, "pam_kmkhomedir", &realm_data, "server", "", &serverhost);

    if (strlen(serverhost) == 0) {
        message = "Please define server in the [appdefaults] section, e.g. \npam_kmkhomedir = {\n     server=hostname\n}";
        goto done;
    }

#ifndef PAM    
    pwd = getpwnam(username);
    if (!pwd) {
        message = "Can't find current user";
        goto done;
    }
#endif

    krb5_appdefault_string(context, "pam_kmkhomedir", &realm_data, "testfile", "", &testfile);
    if (strlen(testfile) > 0) {
        // check to see if the file system is mounted
        char filebuf[1024];
        char *sp;
        struct stat statbuf;

        sp = strrchr(dirname, '/');
        if (sp) {
            *sp = '\0';
            snprintf(filebuf, sizeof(filebuf) - 1, "%s/%s", dirname, testfile);
            if (stat(filebuf, &statbuf) != 0) {
                // test file not there. file system not mounted?
                message = "The file system containging your home directory seems not to be mounted.";
                goto done;
            }
            *sp = '/';
        }

    }

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

    hostname = realhost;

    if ((retval = krb5_build_principal(context, &client, strlen(default_realm), default_realm, "host", hostname, NULL))) {
        message = "Unable to make principal for this host";
        goto done;
    }

    if ((retval = krb5_kt_resolve(context, "/etc/krb5.keytab", &hostkeytab))) {
        message = "unable to get keytab for this host";
        goto done;
    }

    if ((retval = krb5_get_init_creds_keytab(context, &hostcreds, client, hostkeytab, 0,  NULL, NULL))) {
        message = "unable to make credentials for host from keytab";
        goto done;
    }
    have_cred = 1;

    if ((retval = krb5_cc_new_unique(context, "FILE", "/tmp/jjjjj", &ccache))) {
        message = "unable to make credentials file for host";
        goto done;
    }

    if ((retval = krb5_cc_initialize(context, ccache, client))) {
        message = "unable to initialized credentials file for host";
        goto done;
    }                                                                                                                        

    if ((retval = krb5_cc_store_cred(context, ccache, &hostcreds))) {                                                                  message = "unable to store host credentials in host cache";
        goto done;
    }

    (void) signal(SIGPIPE, SIG_IGN);

    portstr = "756";

    memset(&aihints, 0, sizeof(aihints));
    aihints.ai_socktype = SOCK_STREAM;
    aihints.ai_flags = AI_ADDRCONFIG;
    aierr = getaddrinfo(serverhost, portstr, &aihints, &ap);
    if (aierr) {
        message = "error looking up server";
        goto done;
    }
    if (ap == 0) {
        /* Should never happen.  */
        message = "error looking up server";
        goto done;
    }

    retval = krb5_sname_to_principal(context, serverhost, service,
                                     KRB5_NT_SRV_HST, &server);
    if (retval) {
        message = "Error while creating server principal";
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

    if (sock == -1) {
        /* Already printed error message above.  */
        message = "unable to connect to server";
        goto done;
    }
    if (debug)
        mylog(LOG_DEBUG, "connected %d", sock);

    cksum_data.data = serverhost;
    cksum_data.length = strlen(serverhost);

    retval = krb5_sendauth(context, &auth_context, (krb5_pointer) &sock,
                           SAMPLE_VERSION, client, server,
                           AP_OPTS_MUTUAL_REQUIRED,
                           &cksum_data,
                           NULL,
                           ccache, &err_ret, &rep_ret, NULL);

    // username
    xmitlen = htons(strlen(username));
    if ((written = write(sock, (char *)&xmitlen,
                        sizeof(xmitlen))) < 0) {
        message = "write 1 failed";
        goto done;
    }

    if ((written = write(sock, (char *)username,
                                 strlen(username))) < 0) {
        message = "write 2 failed";
        goto done;
    }

    // dirname
    xmitlen = htons(strlen(dirname));
    if ((written = write(sock, (char *)&xmitlen,
                         sizeof(xmitlen))) < 0) {
        message = "write 3 failed";
        goto done;
    }
    if ((written = write(sock, (char *)dirname,
                                 strlen(dirname))) < 0) {
        message = "write 4 failed";
        goto done;
    }
    if (retval && retval != KRB5_SENDAUTH_REJECTED) {
        mylog(LOG_ERR, "sendauth failed: %s", error_message(retval));
        if (retval == KRB5KRB_AP_ERR_BADADDR)
            message = "The official error message is \"Incorrect net address\", but this is usuallly caused when you don't have valid kerberos credentials";
        else
            message = "sendauth failed";
        goto done;
    }

    if (retval == KRB5_SENDAUTH_REJECTED) {
        /* got an error */
        mylog(LOG_ERR, "sendauth rejected, error reply is:\n\t\"%*s\"",
               err_ret->text.length, err_ret->text.data);
        message = "sendauth rejected";
        goto done;
    } else if (rep_ret) {
        /* got a reply */
        krb5_free_ap_rep_enc_part(context, rep_ret);

        if (debug)
            mylog(LOG_DEBUG, "sendauth succeeded, reply is:");

        if ((retval = net_read(sock, (char *)&xmitlen,
                               sizeof(xmitlen))) <= 0) {
            message = "error reading response from server";
            goto done;
        }
        recv_data.length = ntohs(xmitlen);
        if (!(recv_data.data = (char *)malloc((size_t) recv_data.length + 1))) {
            message = "can't allocate memory";
            goto done;
        }
        if (xmitlen > 0) {
            if ((retval = net_read(sock, (char *)recv_data.data,
                                   recv_data.length)) <= 0) {
                message = "error reading response from server";
                goto done;
            }
        } else {
            message = NULL;
        }

        recv_data.data[recv_data.length] = '\0';

    }

 done:
    // message from server is malloc'ed.
    // so caller can always free, have to copy other things into mallocated space.
    
    if (message) {
        char *temp = malloc(strlen(message) + 1);
        strcpy(temp, message);
        message = temp;
    } else {
        message = recv_data.data;
    }

#ifndef PAM
    fprintf(stderr, "%s\n", message);
#endif
    
    if (sock != -1)
        close(sock);
    if (server)
        krb5_free_principal(context, server); 
    if (ccache)
        krb5_cc_close(context, ccache);
    if (have_cred)
        krb5_free_cred_contents(context, &hostcreds);
    if (hostkeytab)
        krb5_kt_close(context, hostkeytab);
    if (client)
        krb5_free_principal(context, client);
    if (context)
        krb5_free_context(context);
    if (apstart)
        freeaddrinfo(apstart);
#ifdef PAM
    return message;
#else
    exit(0);
#endif
}

#ifdef PAM

#define PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <keyutils.h>

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {

  const char *username;
  struct passwd * pwd;
  struct stat statbuf;
  char *message;
  char *serverhost = NULL;
  const char *pattern = NULL;
  char *dir = NULL;
  int freedir = 0;
  int i;

  for (i = 0; i < argc; i++) {
      if (strncmp(argv[i],"host=", strlen("host=")) == 0) 
          serverhost = (char *)argv[i] + strlen("host=");
      if (strncmp(argv[i],"dir=", strlen("dir=")) == 0) 
          pattern = argv[i] + strlen("dir=");
  }

  if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS) {
      pam_syslog(pamh, LOG_ERR, "unable to determine username");
      pam_error(pamh, "Unable to determine username");
      return PAM_SUCCESS; // go ahead and do the login anyway
  }

  pwd = getpwnam(username);
  if (!pwd) {
      pam_syslog(pamh, LOG_ERR, "Can't find current user");
      pam_error(pamh, "Can't find current user");
      return PAM_SUCCESS; // go ahead and do the login anyway
  }

  dir = pwd->pw_dir;
  if (pattern) {
      char *cp = strstr(pattern, "%u");
      if (cp) {
          freedir = 1;  // need to free this
          dir = malloc(strlen(pattern) + strlen(username));
          strncpy(dir, pattern, cp - pattern);
          dir[cp-pattern] = '\0';
          strcat(dir, username);
          strcat(dir, cp + 2);
      }
  }

  if (stat(dir, &statbuf) == 0) {
      // directory already exists
      if (freedir)
          free(dir);
      return PAM_SUCCESS;
  }

  if (errno != ENOENT) {
      pam_syslog(pamh, LOG_ERR, "Error tryibg to look up directory %m");
      pam_error(pamh, "Error tryibg to look up directory %m");
      // not really success, but we probably don't want to stop login
      if (freedir)
          free(dir);
      return PAM_SUCCESS;
  }

  // at this point directory doesn't exist. no other error
  message = pam_kmkhomedir(dir, pwd, serverhost);

  if (strlen(message) > 0) {
      pam_syslog(pamh, LOG_ERR, "%s", message);
      pam_error(pamh, "Unable to create home directory: %s", message);
  }

  free(message);
  if (freedir)
      free(dir);

  return PAM_SUCCESS;

}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  return PAM_SUCCESS;
} 

#endif
