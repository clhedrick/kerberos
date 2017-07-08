/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/* ldap using gssapi, and ldap utility code for credserv */

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
#include <ldap.h>
#include <sasl/sasl.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sample.h"
#include "credldap.h"

extern krb5_deltat krb5_clockskew;

int debug = 0;

// credentaisl is a list of lists. 

#define GENERIC_ERR "Unable to get credentials"
#define NOKEYTAB_ERR "You must register a keytable for this host before you can use this program."

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

/*
 * callback for sasl_interactive_bind
 * taken from IPA source. I don't see any way to have guessed this from 
 * documentation.
 */

static int ldap_sasl_interact(LDAP *ld, unsigned flags, void *priv_data, void *sit)
{
    sasl_interact_t *in = NULL;
    int ret = LDAP_OTHER;
    krb5_principal princ = (krb5_principal)priv_data;
    krb5_context krbctx;
    char *outname = NULL;
    krb5_error_code krberr;

    if (!ld) return LDAP_PARAM_ERROR;

    for (in = sit; in && in->id != SASL_CB_LIST_END; in++) {
        switch(in->id) {
        case SASL_CB_USER:
            krberr = krb5_init_context(&krbctx);

            if (krberr) {
                mylog(LOG_ERR, "Kerberos context initialization failed: %s (%d)", error_message(krberr), krberr);
		in->result = NULL;
                in->len = 0;
                ret = LDAP_LOCAL_ERROR;
                break;
            }

            krberr = krb5_unparse_name(krbctx, princ, &outname);

            if (krberr) {
                mylog(LOG_ERR, "Unable to parse principal: %s (%d)", error_message(krberr), krberr);
                in->result = NULL;
                in->len = 0;
                ret = LDAP_LOCAL_ERROR;
                break;
            }

            in->result = outname;
            in->len = strlen(outname);
            ret = LDAP_SUCCESS;

            krb5_free_context(krbctx);

            break;
        case SASL_CB_GETREALM:
            in->result = princ->realm.data;
            in->len = princ->realm.length;
            ret = LDAP_SUCCESS;
            break;
        default:
            in->result = NULL;
            in->len = 0;
            ret = LDAP_OTHER;
        }
    }
    return ret;
}

int  auth_method    = LDAP_AUTH_SASL;
int desired_version = LDAP_VERSION3;

// data fot testing
// these are passed as arguments from credserv in real usage
char *grealm = "CS.RUTGERS.EDU";
char *gservice = "credserv";
char *ghostname = "krb1.cs.rutgers.edu";
char *targetuser = "hedrick";

// a fairly generic ldap open with GSSAPI
// for a server. for a client a lot of this code isn't needed
// since most of it is setting up a credentials cache for the server's principal

LDAP *krb_ldap_open(krb5_context context, char *service, char *hostname, char *realm) {
    LDAP *ld = NULL;
    int  ret;
    krb5_principal bind_princ = NULL;
    krb5_error_code retval;
    krb5_keytab keytab = NULL;
    krb5_ccache cache = NULL;
    krb5_creds servcreds;
    int havecreds = 0;
    char *putstr = NULL;
    char *ldapurl;
    krb5_data realm_data;
    char *oldval = NULL;
    char *oldvalcopy = NULL;
    int resetenv = 0;

    realm_data.data = realm;
    realm_data.length = strlen(realm);

    krb5_appdefault_string(context, "credserv", &realm_data, "ldapurl", "ldaps://localhost", &ldapurl);

    // first we have to set up a credentials file with creds for the credserv/HOST
    // that's used by the GSSAPI authentication

    if ((retval = krb5_kt_resolve(context, "/etc/krb5.keytab", &keytab))) {
        mylog(LOG_ERR, "unable to open /etc/krb5.keytab");
        goto err;
    }

    retval = krb5_build_principal(context, &bind_princ, strlen(realm), realm, service, hostname, NULL);
    if (retval) {
        mylog(LOG_ERR, "failure building kerberos principal for credserv service");
        goto err;
    }

    if ((retval = krb5_get_init_creds_keytab(context, &servcreds, bind_princ, keytab, 0,  NULL, NULL))) {
        mylog(LOG_ERR, "unable to make credentials for service from keytab %s", error_message(retval));
        goto err;
    }
    havecreds = 1;

    // put it in a temporary cache, since we just need it internally
    if ((retval = krb5_cc_new_unique(context, "MEMORY", "/tmp/jjjjj", &cache))) {
        mylog(LOG_ERR, "unable to make credentials file for service %s", error_message(retval));
        goto err;
    }

    if ((retval = krb5_cc_initialize(context, cache, bind_princ))) {
        mylog(LOG_ERR, "unable to initialize credentials file for service %s", error_message(retval));
        goto err;
    }

    if ((retval = krb5_cc_store_cred(context, cache, &servcreds))) {
        mylog(LOG_ERR, "unable to store user credentials in cache %s", error_message(retval));
        goto err;
    }

    oldval = getenv("KRB5CCNAME");
    // memory is inside libc, doesn't get returned
    // putenv may overwrite, so copy it
    if (oldval) {
        oldvalcopy = malloc(strlen(oldval) + 1);
        strcpy(oldvalcopy, oldval);
    }
    resetenv = 1;

    asprintf(&putstr, "KRB5CCNAME=MEMORY:%s", krb5_cc_get_name(context, cache));
    putenv(putstr);
    // can't release this string, as it becomes part of the env

    // make sure everything is written before we use it
    krb5_cc_close(context, cache);
    cache = NULL;

    // now we have the credentials file set up, do LDAP with GSSAPI

    ldap_initialize (&ld, ldapurl);
    if (ld == NULL) {
        mylog(LOG_ERR, "ldap_initialize failed");
        goto err;
    }

    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &desired_version) != LDAP_OPT_SUCCESS) {
        mylog(LOG_ERR, "ldap_set_option failed");
        goto err;
    }

    ret = ldap_sasl_interactive_bind_s(ld, NULL, "GSSAPI", NULL, NULL, LDAP_SASL_QUIET, ldap_sasl_interact, bind_princ);
    if (ret != LDAP_SUCCESS) {
        mylog(LOG_ERR, "ldap_sasl_bind_s: %s", ldap_err2string(ret));
    }

    goto ok;

 err:
    if (ld)
        ldap_unbind_ext(ld, NULL, NULL);
    ld = NULL;
 ok:
    if (resetenv) {
        if (oldvalcopy) {
            asprintf(&putstr, "KRB5CCNAME=%s", oldvalcopy);
            putenv(putstr); // becomes part of env, don't free it
            free(oldvalcopy); // but this is no longer needed
        } else {
            unsetenv("KRB5CCNAME");
        }
    }
    if (cache)
      krb5_cc_close(context, cache);
    if (havecreds)
        krb5_free_cred_contents(context, &servcreds);
    if (keytab)
        krb5_kt_close(context, keytab);
    if (bind_princ) 
        krb5_free_principal(context, bind_princ);

    return ld;

}

// read rules and keytab from ldap

int getLdapData(krb5_context context, LDAP *ld, char* realm,  char *user, struct berval ***rules, struct berval***keytab, char **dn) {
    char* filter;
    LDAPMessage* msg;
    BerElement* ber;
    LDAPMessage *entry;
    char* attr;
    char *base;
    krb5_data realm_data;

    realm_data.data = realm;
    realm_data.length = strlen(realm);

    krb5_appdefault_string(context, "credserv", &realm_data, "ldapbase", "", &base);

    asprintf(&filter, "(uid=%s)", user);

    if (ldap_search_ext_s(ld, base, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
        mylog(LOG_ERR, "ldap_search_s failed");
        free(filter);
        return 1;
    }
    free(filter);

    entry = ldap_first_entry(ld, msg);
    if (entry == NULL) {
        mylog(LOG_ERR, "no ldap entry for %s", user);
        return 1;
    }

    *dn = ldap_get_dn(ld, entry);

    *rules = NULL; // if no rules defined
    *keytab = NULL; // if no keytab defined
    for (attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
        if (strcmp(attr, "csRutgersEduCredservRule") == 0) {
            *rules = ldap_get_values_len(ld, entry, attr);
        } else if (strcmp(attr, "csRutgersEduCredservKeytab") == 0) {
            *keytab = ldap_get_values_len(ld, entry, attr);
        }
        ldap_memfree(attr);
    }
    if (ber)
        ber_free(ber, 0);
    ldap_msgfree(msg);

    return 0;

}

// free all data structures returned by above
// I don't actually use this. credserv forks, and there's no
// reason to clean up memory when it's about to exit

void freeLdapData(struct berval **rules, struct berval **keytab, char *dn) {
    if (rules)
        ldap_value_free_len(rules);
    if (keytab)
        ldap_value_free_len(keytab);
    if (dn)
        ldap_memfree(dn);
}

// add a credserv authorization rule into ldap

int addRule(LDAP *ld, char *dn, char *rule) {
    LDAPMod rulemod;
    LDAPMod *mods[2];
    char *rulevalues[2];
    int ret;

    /* Initialize the attribute, specifying 'REPLACE' as the operation */
    rulemod.mod_op     = LDAP_MOD_ADD;
    rulemod.mod_type   = "csRutgersEduCredservRule";
    rulevalues[0] = rule;
    rulevalues[1] = NULL;
    rulemod.mod_values = rulevalues;

    /* Fill the attributes array (remember it must be NULL-terminated) */
    mods[0] = &rulemod;
    mods[1] = NULL;

    if ((ret = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
        mylog(LOG_ERR, "ldap_modify for add: %s", ldap_err2string(ret));
        return 1;
    }

    return 0;
}

// delete a credserv authorization rule from ldap

int deleteRule(LDAP *ld, char *dn, char *rule) {
    LDAPMod rulemod;
    LDAPMod *mods[2];
    char *rulevalues[2];
    int ret;

    /* Initialize the attribute, specifying 'REPLACE' as the operation */
    rulemod.mod_op     = LDAP_MOD_DELETE;
    rulemod.mod_type   = "csRutgersEduCredservRule";
    rulevalues[0] = rule;
    rulevalues[1] = NULL;
    rulemod.mod_values = rulevalues;

    /* Fill the attributes array (remember it must be NULL-terminated) */
    mods[0] = &rulemod;
    mods[1] = NULL;

    if ((ret = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
        mylog(LOG_ERR, "ldap_modify for add: %s", ldap_err2string(ret));
        return 1;
    }

    return 0;
}

// update the key table for a user.
// this will create a new one or update the existing one

int replaceKeytab(LDAP *ld, char *dn, struct berval **keytab, struct berval *newkeytab) {
    LDAPMod rulemod;
    LDAPMod *mods[2];
    struct berval *rulevalues[2];
    int ret;
    int i;
    // number of chars in prefix of new value, i.e. up through and including =
    char *newtext = newkeytab->bv_val;
    int preflen = (strchr(newtext, '=') - newtext) + 1;

    // remove any value for this principal
    if (keytab && keytab[0] != NULL) {
        for (i = 0; keytab[i] != NULL; i++) {
            char *thistext;
            thistext = keytab[i]->bv_val;
            if (strncmp(thistext, newtext, preflen) == 0) {
                // this entry is for this principal, so we need to delete it
                rulemod.mod_op     = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
                rulemod.mod_type   = "csRutgersEduCredservKeytab";
                rulevalues[0] = keytab[i];
                rulevalues[1] = NULL;
                rulemod.mod_bvalues = rulevalues;

                mods[0] = &rulemod;
                mods[1] = NULL;

                if ((ret = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
                    mylog(LOG_ERR, "ldap_modify failed to remove old keytab: %s", ldap_err2string(ret));
                    return 1;
                }
            }
        }
    }

    /* Initialize the attribute, specifying 'REPLACE' as the operation */
    rulemod.mod_op     = LDAP_MOD_ADD | LDAP_MOD_BVALUES;
    rulemod.mod_type   = "csRutgersEduCredservKeytab";
    rulevalues[0] = newkeytab;
    rulevalues[1] = NULL;
    rulemod.mod_bvalues = rulevalues;

    /* Fill the attributes array (remember it must be NULL-terminated) */
    mods[0] = &rulemod;
    mods[1] = NULL;

    if ((ret = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
        mylog(LOG_ERR, "ldap_modify for add: %s", ldap_err2string(ret));
        return 1;
    }

    return 0;
}

// delete the keytab for this user from ldap

int deleteKeytab(LDAP *ld, char *dn, struct berval **keytab, char *principal) {
    LDAPMod rulemod;
    LDAPMod *mods[2];
    struct berval *rulevalues[2];
    int ret;
    char *prefix;
    int preflen = strlen(principal) + 1;
    int i;

    asprintf(&prefix, "%s=", principal);

    // remove any value for this principal
    if (keytab && keytab[0] != NULL) {
        for (i = 0; keytab[i] != NULL; i++) {
            char *thistext;
            thistext = keytab[i]->bv_val;
            if (strncmp(thistext, prefix, preflen) == 0) {
                // this entry is for this principal, so we need to delete it
                rulemod.mod_op     = LDAP_MOD_DELETE | LDAP_MOD_BVALUES;
                rulemod.mod_type   = "csRutgersEduCredservKeytab";
                rulevalues[0] = keytab[i];
                rulevalues[1] = NULL;
                rulemod.mod_bvalues = rulevalues;

                mods[0] = &rulemod;
                mods[1] = NULL;

                if ((ret = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
                    mylog(LOG_ERR, "ldap_modify failed to remove old keytab: %s", ldap_err2string(ret));
                    return 1;
                }
            }
        }
    }

    return 0;
}

#ifdef MAIN
int main(int argc, char *argv[]) {

    krb5_context context;
    krb5_error_code retval;
    char* filter;
    LDAPMessage* msg;
    BerElement* ber;
    LDAP *ld;
    LDAPMessage *entry;
    char* attr;
    struct berval **rules;
    struct berval **keytab;
    struct berval newkeytab;
    struct berval **vals;
    int i;
    char *base;
    krb5_data realm_data;
    char *dn = NULL;
    int ret;
    char *foovalues[] = {"foobar", NULL};
    LDAPMod foo;
    LDAPMod *mods[2];

    retval = krb5_init_context(&context);
    if (retval) {
        com_err(argv[0], retval, "while initializing krb5");
        exit(1);
    }

    unsetenv("KRB5CCNAME");

    ld = krb_ldap_open(context, gservice, ghostname, grealm);

    printf("env %s\n", getenv("KRB5CCNAME"));

#ifdef undef    
    if (getLdapData(context, ld, grealm, targetuser, &rules, &keytab, &dn) == 0) {
        printf("dn %s\n", dn);
        if (rules) {
            for(i = 0; rules[i] != NULL; i++) {
                printf("rule: %s\n", rules[i]->bv_val);
            }
        }
        if (keytab) {
            for(i = 0; keytab[i] != NULL; i++) {
                printf("keytab: %s\n", keytab[i]->bv_val);
            }
        }
    }

    deleteRule(ld, dn, "fake rule");

    newkeytab.bv_len = strlen("fake keytab");
    newkeytab.bv_val = "fake keytab";
    replaceKeytab(ld, dn, &newkeytab);

    freeLdapData(rules, keytab, dn);

    realm_data.data = grealm;
    realm_data.length = strlen(grealm);

    krb5_appdefault_string(context, "credserv", &realm_data, "ldapbase", "", &base);

    /* search from this point */
     
    asprintf(&filter, "(uid=%s)", targetuser);

    if (ldap_search_ext_s(ld, base, LDAP_SCOPE_SUBTREE, filter, NULL, 0, NULL, NULL, NULL, 0, &msg) != LDAP_SUCCESS) {
        perror("ldap_search_s" );
    }
    free(filter);

    for (entry = ldap_first_entry(ld, msg); entry != NULL; entry = ldap_next_entry(ld, entry)) {
        dn = ldap_get_dn(ld, entry);
        printf("dn: %s\n", dn);
        for( attr = ldap_first_attribute(ld, entry, &ber); attr != NULL; attr = ldap_next_attribute(ld, entry, ber)) {
            if ((vals = ldap_get_values_len(ld, entry, attr)) != NULL)  {
                for(i = 0; vals[i] != NULL; i++) {
                    printf("%s: %s\n", attr, vals[i]->bv_val);
                }
                ldap_value_free_len(vals);
            }
            ldap_memfree(attr);
        }
        if (ber)
            ber_free(ber, 0);
        printf("\n");
    }
    ldap_msgfree(msg);


    /* Initialize the attribute, specifying 'REPLACE' as the operation */
    foo.mod_op     = LDAP_MOD_REPLACE;
    foo.mod_type   = "csRutgersEduCredservKeytab";
    foo.mod_values = foovalues;

    /* Fill the attributes array (remember it must be NULL-terminated) */
    mods[0] = &foo;
    mods[1] = NULL;

    if ((ret = ldap_modify_ext_s(ld, dn, mods, NULL, NULL)) != LDAP_SUCCESS) {
        mylog(LOG_ERR, "ldap_sasl_bind_s: %s", ldap_err2string(ret));
    }

    ldap_memfree(dn);
#endif

    return 0;
    
}
#endif
