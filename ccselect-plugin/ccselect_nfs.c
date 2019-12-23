/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* lib/krb5/ccache/ccselect_k5identity.c - k5identity ccselect module */
/*
 * Copyright 2019 by Rutgers, the State University of New Jersey
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

#include <krb5.h>
#include <krb5/ccselect_plugin.h>
#include <ctype.h>
#include <string.h>
#include <pwd.h>
#include <stdio.h>

// creds must have 2 min left. It's silly to start without that
// we have to at least check that there's some time, or we could return
// an expired cache, so might as well ignore caches about to expire
// hope /tmp has something better
#define MINLEFT (2 * 60)

static inline int
data_eq(krb5_data d1, krb5_data d2)
{
  return (d1.length == d2.length && (d1.length == 0 ||
				     !memcmp(d1.data, d2.data, d1.length)));
}

static inline int
data_eq_string (krb5_data d, const char *s)
{
    return (d.length == strlen(s) && (d.length == 0 ||
                                      !memcmp(d.data, s, d.length)));
}

krb5_boolean is_local_tgt (krb5_principal princ, krb5_data *realm);

/* Return true if princ is the local krbtgt principal for local_realm. */
krb5_boolean
is_local_tgt(krb5_principal princ, krb5_data *realm)
{
  return princ->length == 2 && data_eq(princ->realm, *realm) &&
    data_eq_string(princ->data[0], KRB5_TGS_NAME) &&
    data_eq(princ->data[1], *realm);
}


// find priority of a cache. It's the end time for the tgt, if any
static uint32_t
cache_priority(krb5_context context, krb5_ccache cache, krb5_principal princ) {
    krb5_cc_cursor cur = NULL;
    krb5_creds creds;
    krb5_boolean found_tgt, found_current_tgt;
    int ret = 0;
    time_t now = time(0);

    // loop over credentials in cache. for the tgt, return end time, or 0 if invalid                                  
    // try to init cursor for loop over cache                                                                         
    if (krb5_cc_start_seq_get(context, cache, &cur) != 0) {
        if (cur)
            krb5_cc_end_seq_get(context, cache, &cur);
        return 0;
    }

    // typically there's only one tgt. I suspect if there's more than one, the first                                  
    // is used. So just look for the first                                                                            
    while (krb5_cc_next_cred(context, cache, &cur, &creds) == 0) {
        // (uint32_t) is a date 2106 issue, but need the cast for 2038
        if (is_local_tgt(creds.server, &princ->realm) &&
            ((time_t)(uint32_t)creds.times.endtime - now) > MINLEFT) {
            // not sure what we'd do with error, so don't check
            krb5_free_cred_contents(context, &creds);
            krb5_cc_end_seq_get(context, cache, &cur);
            return (uint32_t)creds.times.endtime;
        } else
            krb5_free_cred_contents(context, &creds);
    }

    krb5_cc_end_seq_get(context, cache, &cur);
    return 0;

}

static krb5_error_code
ccselect_nfs_init(krb5_context context, krb5_ccselect_moddata *data_out,
                int *priority_out)
{
    *data_out = NULL;
    // use low priority so that an explicit entry in .k5select overrides
    *priority_out = KRB5_CCSELECT_PRIORITY_HEURISTIC;
    return 0;
}

static krb5_error_code
ccselect_nfs_choose(krb5_context context, krb5_ccselect_moddata data,
                  krb5_principal server, krb5_ccache *cache_out,
                  krb5_principal *princ_out)
{
    char *str;

    // with ubuntu 16, this gets called for the machine credentials
    // if we let this code trigger it would try to find a credential for root
    // rather than host/MACHINE. so only use this if euid != 0
    if (geteuid() != 0 && ! krb5_unparse_name(context, server, &str)) {
        // only do this for NFS, where the service principal is nfs/...
        if (strncmp(str, "nfs/", 4) == 0) {
            char pwbuf[1024]; // for strings in the pwd struct
            struct passwd passwd;  // for the pwd struct
            struct passwd *pwd = NULL;  // the actual return value, pointer to passwd or NULL
            krb5_principal princ = NULL;

            krb5_free_unparsed_name(context, str);
            // ignore return value, because checking pwd NULL will also work
            getpwuid_r(geteuid(), &passwd, pwbuf, sizeof(pwbuf), &pwd);
            if (pwd && pwd->pw_name) {
                if (krb5_parse_name(context, pwd->pw_name, &princ) == 0) {
                    // found the principal. But if we just return it, the library
                    // will use the first cache with this principal. However it
                    // might be about to expire. We want the best cache with this
                    // principal
                    krb5_cccol_cursor cursor;
                    krb5_ccache cache;
                    krb5_ccache bestcache = NULL;
                    uint32_t bestpriority = 0;
                    krb5_principal cc_princ = NULL;

                    if (krb5_cccol_cursor_new(context, &cursor) != 0) {
                        krb5_free_principal(context, princ);
                        return KRB5_PLUGIN_NO_HANDLE;
                    }
                    while (krb5_cccol_cursor_next(context, cursor, &cache) == 0 &&
                           cache != NULL) {
                        // loop over caches
                        // what's the principal
                        krb5_cc_get_principal(context, cache, &cc_princ);
                        
                        if (cc_princ && krb5_principal_compare(context, princ, cc_princ)) {
                            uint32_t priority = cache_priority(context, cache, cc_princ);
                            if (priority > bestpriority) {
                                bestpriority = priority;
                                if (bestcache)
                                    krb5_cc_close(context, bestcache);
                                bestcache = cache;
                            } else 
                                krb5_cc_close(context, cache);             
                        } else
                            krb5_cc_close(context, cache);
                        krb5_free_principal(context, cc_princ);
                        cc_princ = NULL;
                    }
                    krb5_cccol_cursor_free(context, &cursor);

                    // if we don't find anything want to return an explicit fail, not NOHANDLE
                    // if we don't, another module may find a cache that is expired or has a silly
                    // small lifetime. We want gssd to go on and check /tmp files, which it won't
                    // if another module finds an unusable KEYRING or KCM
                    if (bestpriority > 0) {
                        *cache_out = bestcache;
                        *princ_out = princ;
                        return 0;
                    } else {
                        // if bestpriority is 0, bestcache wasn't allocated
                        krb5_free_principal(context, princ);
                        *cache_out = NULL;
                        *princ_out = NULL;
                        // this is different from NOHANDLE, because it's authoritative
                        // if we return KRB5_CC_NOTFOUND with a principal, gssd can find
                        // expired tickets for that principal
                        return KRB5_NO_TKT_SUPPLIED;
                    }

                }
            }
        } else
            krb5_free_unparsed_name(context, str);

    }

    return KRB5_PLUGIN_NO_HANDLE;

}

krb5_error_code
ccselect_nfs_initvt(krb5_context context, int maj_ver, int min_ver,
                           krb5_plugin_vtable vtable)
{

    krb5_ccselect_vtable vt;

    if (maj_ver != 1)
        return KRB5_PLUGIN_VER_NOTSUPP;
    vt = (krb5_ccselect_vtable)vtable;
    vt->name = "nfs";
    vt->init = ccselect_nfs_init;
    vt->choose = ccselect_nfs_choose;
    return 0;
}

#ifdef TEST

int main(int argc, char **argv) {
    krb5_context context;
    char data[100];  // ignored
    krb5_principal server;
    krb5_principal princ;
    int ret;
    krb5_ccache cache;

    setuid(1003);

    krb5_init_context(&context);
    krb5_parse_name(context, "nfs/koko.lcsr.rutgers.edu", &server);

    
    ret = ccselect_nfs_choose(context, (krb5_ccselect_moddata)data, server, &cache, &princ);

    printf("ret %d\n", ret);
    if (cache) {
        printf("cache %s\n", krb5_cc_get_name(context, cache));
        krb5_cc_close(context, cache);
    }
        
    if (princ) {
        char *name;
        krb5_unparse_name(context, princ, &name);
        printf("princ %s\n", name);
        krb5_free_unparsed_name(context, name);
        krb5_free_principal(context, princ);
    }

    krb5_free_principal(context, server);
    krb5_free_context(context);

    
}

#endif
