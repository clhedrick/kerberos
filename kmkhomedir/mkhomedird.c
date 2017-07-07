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
#include <pwd.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sample.h"

#define CONFFILE "/etc/mkhomedird.conf"

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

int isprived(char *principal);

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
    GETPEERNAME_ARG3_TYPE  namelen = sizeof(peername);
    int sock = -1;                      /* incoming connection fd */
    short xmitlen;
    krb5_error_code retval;
    krb5_principal server;
    char *service = "mkhomedird";
    short port = 756;             /* If user specifies port */
    extern int opterr, optind;
    extern char * optarg;
    int ch;
    krb5_keytab keytab = NULL;
    char *progname;
    int on = 1;
    // args from kgetcred
    char *username;
    char *directory;
    krb5_creds usercreds;
    int i;
    char *message = "";
    struct passwd *pwd;
    krb5_data realm_data;
    char *default_realm = NULL;
    char *homedirstr = NULL;
    char **homedirs = NULL;
    char *cp;
    char *testfile = NULL;

    // in case we're run by a user from the command line, get a known environment
    clearenv();

    memset(&usercreds, 0, sizeof(usercreds));

    progname = *argv;

    /* open a log connection */
    openlog("mkhomedird", 0, LOG_DAEMON);

    retval = krb5_init_context(&context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
        exit(1);
    }

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

    if ((retval = krb5_get_default_realm(context, &default_realm))) {
        com_err(argv[0], retval, "getting default realm");
        exit(1);
    }

    realm_data.data = default_realm;
    realm_data.length = strlen(default_realm);

    krb5_appdefault_string(context, "mkhomedird", &realm_data, "homedirs", "", &homedirstr);
    if (strlen(homedirstr) == 0) {
        mylog(LOG_ERR, "Please define valid home directories in the [appdefaults] section, e.g. \nmkhomedird = {\n     homedirs=/home,/home2\n");
        exit(1);
    }

    i = 1;
    cp = homedirstr;
    for (cp = homedirstr; *cp; cp++) {
        if (*cp == ',')
            i++;
    }
    homedirs = malloc(sizeof(char *) * (i + 1));
    i = 0;
    for (cp = strtok(homedirstr, ", "); cp; cp = strtok(NULL, ", ")) {
        homedirs[i] = cp;
        i++;
    }
    homedirs[i] = NULL;

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
        struct sockaddr_in6 sockin;
        memset(&sockin, 0, sizeof(sockin));

        if ((sock = socket(PF_INET6, SOCK_STREAM, 0)) < 0) {
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
        while (1) {
            namelen = sizeof(peername_storage);
            if ((acc = accept(sock, peername, &namelen)) == -1){
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
        namelen = sizeof(peername_storage);
        /*
         * To verify authenticity, we need to know the address of the
         * client.
         */
        if (getpeername(0, peername, &namelen) < 0) {
            mylog(LOG_DEBUG, "getpeername: %m");
            exit(1);
        }
        sock = 0;
    }

    mylog(LOG_DEBUG, "connection from %s", ntoa(peername));

    retval = krb5_recvauth(context, &auth_context, (krb5_pointer)&sock,
                           SAMPLE_VERSION, server,
                           0,   /* no flags */
                           keytab,      /* default keytab is NULL */
                           &ticket);
    if (retval) {
        printf("retval %d", retval);
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }

    // get arguments from kgetcred: operation, username and principal

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

    // directory
    if ((retval = net_read(sock, (char *)&xmitlen,
                           sizeof(xmitlen))) <= 0) {
        if (retval == 0)
            errno = ECONNABORTED;
        mylog(LOG_ERR, "recvauth failed--%s", error_message(retval));
        exit(1);
    }
    xmitlen = ntohs(xmitlen);
    if (!(directory = (char *)malloc((size_t) xmitlen + 1))) {
        mylog(LOG_ERR, "no memory while allocating buffer to read from client");
        exit(1);
    }
    if ((retval = net_read(sock, (char *)directory,
                           xmitlen)) <= 0) {
        mylog(LOG_ERR, "connection abort while reading data from client");
        exit(1);
    }
    directory[xmitlen] = '\0';

    cp = strrchr(directory, '/');
    if (!cp) {
        message = "Invalid directory name";
        goto done;
    }
    *cp = '\0';

    if (strcmp(cp+1, username) != 0) {
        message = "Directory name must end in username";
        goto done;
    }

    pwd = getpwnam(username);
    if (!pwd) {
        message = strerror(errno);
        goto done;
    }

    // now compare directory prefix with legal ones.
    for (i = 0; homedirs[i]; i++) {
        if (strcmp(homedirs[i], directory) == 0)
            break;
    }
    if (homedirs[i] == NULL) {
        // search went off send, i.e. not found
        message = "directory not authorized";
        goto done;
    }

    // now see if the file system is mounted, if asked to do so
    // note that directory still has the last component removed
    krb5_appdefault_string(context, "mkhomedird", &realm_data, "testfile", "", &testfile);
    if (strlen(testfile) > 0) {
        // check to see if the file system is mounted
        char filebuf[1024];
        struct stat statbuf;

        snprintf(filebuf, sizeof(filebuf) - 1, "%s/%s", directory, testfile);
        if (stat(filebuf, &statbuf) != 0) {
            // test file not there. file system not mounted?
            message = "The file system containging your home directory seems not to be mounted on the server.";
            goto done;
        }
    }

    // put back the / between prefix and username, we turned into into nul above
    *cp = '/'; 

    i = mkdir(directory, 0700);
    if (i && errno != EEXIST) {
        message = strerror(errno);
        goto done;
    }

    i = chown(directory, pwd->pw_uid, pwd->pw_gid);
    if (i) {
        message = strerror(errno);
        goto done;
    }

    message = "";

done:
    mylog(LOG_DEBUG, "returning message to client %s for user %s %s", ntoa(peername), username, message);

    xmitlen = htons(strlen(message));
    if ((retval = krb5_net_write(context, 0, (char *)&xmitlen,
                                 sizeof(xmitlen))) < 0) {
        mylog(LOG_ERR, "%m: while writing len to client");
        exit(1);
    }

    if (xmitlen != 0) {
        if ((retval = krb5_net_write(context, 0, message, strlen(message))) < 0) {
            mylog(LOG_ERR, "%m: while writing len to client");
            exit(1);
        }
    }

    // no cleanup since we're forked

    exit(0);
}

