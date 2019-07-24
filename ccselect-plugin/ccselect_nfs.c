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

#include <pwd.h>

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

    if (! krb5_unparse_name(context, server, &str)) {
        if (strncmp(str, "nfs/") == 0) {
            char pwbuf[1024]; // for strings in the pwd struct
            struct passwd passwd;  // for the pwd struct
            struct passwd *pwd;  // the actual return value, pointer to passwd or NULL
            krb5_principal princ = NULL;

            krb5_free_unparsed_name(context, str);
            // ignore return value, because checking pwd NULL will also work
            getpwuid_r(geteuid(), &passwd, pwbuf, sizeof(pwbuf), &pwd);
            if (pwd && pwd->pw_name) {
                if (krb5_parse_name(context, pwd->pw_name, &princ) == 0) {
                    *princ_out = princ;
                    *cache_out = NULL;
                    return 0;
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
    vt->name = "clh";
    vt->init = ccselect_nfs_init;
    vt->choose = ccselect_nfs_choose;
    return 0;
}

