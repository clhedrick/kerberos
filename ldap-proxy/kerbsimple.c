/*

 * Copyright 2017 Rutgers, the State University of New Jersey
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.

This is an overlay to do Kerberos password checking. It's intended for
use where you have some systems that can't use Kerberos, but need to
check passwords.  The intent is to point nslcd at an OpenLDAP proxy
using this overlay. Nothing requires the database to be LDAP, but I'm
not sure how useful it would be in other cases.

The operation is a bit peculiar, because I didn't have time to reverse
engineer as much about Openldap as I'd like. nslcd and things like it
do 2 things:
* get information about users and groups, for nssswitch
* check user passwords
I assume that nslcd is configured to bind to a user that has permission
to get the information about users and groups. The DN of that user
must be configured as olcKerbsimpleAdminDN. This overlay will pass binds
for that user through to the backend, since it may need permissions.

All other binds are assumed to be for checking a user's password. They
are processed by Kerberos, with the result returned immediately. That
is, the bind isn't passed to the backend (because it would fail there).
If you figure out how to use the idassert feature, you might want to
modify the code in kerbsimple_bind to fail cases that fail, and pass
the ones that succeed through to the back end, asserting the user's
identify.

The same task could in some cases be done using SASL authentiction to
openldap. However that requires creating an attribute for each user,
something like {KRB5}user@domain.  In our situation the underlying
database is another LDAP server, and it doesn't have those attributes.
As far as we can tell, Openldap can't create virtual attributes like
that. Also, we use one-time passwords with Kerberos. Most Kerberos
support code can't handle them. This code can.

*/


#include "portable.h"

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "config.h"

#include <krb5.h>
#include <com_err.h>

#define OTPPROMPT  "Enter OTP Token Value"

static slap_overinst kerbsimple;

// configuration info is kept in this structure

// the admin DN, i.e. the one dn where binds are passed to the back end
// a keytable, used to generate credentials to "armor" (encrypt) passwords
//    sent to the KDC. This is a new feature of Kerberos, useful only when
//    one-time passwords are being used.
// the principal stored in that key table.

typedef struct kerbsimple_data {
  char *ks_admindn;
  char *ks_armorkeytab;
  char *ks_armorprincipal;
} kerbsimple_data;

// defines the attributes used to specify the configuration info above.

// I'm using OIDs from Rutgers space, 1.3.6.1.4.1.10962, since it's not
// safe to use the space allocated to openldap.

static ConfigTable kerbsimplecfg[] = {
	{ "admin-dn", "adminDn", 2, 2, 0,
	  ARG_STRING|ARG_OFFSET,
	  (void *)offsetof(kerbsimple_data, ks_admindn),
	  "( 1.3.6.1.4.1.10962.2.4.4 NAME 'olcKerbsimpleAdminDN' "
	  "DESC 'DN used by clients to fetch information' "
	  "SYNTAX OMsDirectoryString SINGLE-VALUE)", NULL, NULL },
	{ "armor-keytab", "filename", 2, 2, 0,
	  ARG_STRING|ARG_OFFSET,
	  (void *)offsetof(kerbsimple_data, ks_armorkeytab),
	  "( 1.3.6.1.4.1.10962.2.4.5 NAME 'olcKerbsimpleArmorKeytab' "
	  "DESC 'Key table used to armor requests' "
	  "SYNTAX OMsDirectoryString SINGLE-VALUE)", NULL, NULL },
	{ "armor-principal", "principal name", 2, 2, 0,
	  ARG_STRING|ARG_OFFSET,
	  (void *)offsetof(kerbsimple_data, ks_armorprincipal),
	  "( 1.3.6.1.4.1.10962.2.4.6 NAME 'olcKerbsimpleArmorPrincipal' "
	  "DESC 'Principal used to armor requests, key must be in ArmorKeytab' "
	  "SYNTAX OMsDirectoryString SINGLE-VALUE)", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

// used to generate the LDAP objectclass for us

static ConfigOCs kerbsimpleocs[] = {
	{ "( 1.3.6.1.4.1.10962.2.4.7 "
	  "NAME 'olcKerbsimpleConfig' "
	  "DESC 'Authenticate simple binds with Kerberos' "
	  "SUP olcOverlayConfig "
	  "MAY (olcKerbsimpleAdminDN $ olcKerbsimpleArmorKeytab $ olcKerbsimpleArmorPrincipal) )",
	  Cft_Overlay, kerbsimplecfg },
	{ NULL, 0, NULL }
};

// called for every instance of this code
// used to set up the kerbsimple_data struct
// where configuration info for this instance is put

static int
kerbsimple_db_init(
	BackendDB	*be,
	ConfigReply	*cr
)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	kerbsimple_data *ad = ch_calloc(1, sizeof(kerbsimple_data));

	on->on_bi.bi_private = ad;
	ad->ks_admindn = NULL;
	ad->ks_armorkeytab = NULL;
	ad->ks_armorprincipal = NULL;

	Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_db_init\n", 0, 0, 0);

	return 0;
}

// called when an instance of this code is destroyed.
// returns the dynamically allocated memory.

static int
kerbsimple_db_destroy(
	BackendDB	*be,
	ConfigReply	*cr
)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	kerbsimple_data *ad = on->on_bi.bi_private;

	Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_db_destroy\n", 0, 0, 0);

	if (ad->ks_admindn)
	  free(ad->ks_admindn);
	if (ad->ks_armorkeytab)
	  free(ad->ks_armorkeytab);
	if (ad->ks_armorprincipal)
	  free(ad->ks_armorprincipal);

	free(ad);

	return 0;
}


// Normally you can call krb5_get_init_creds_password and hand it a password
// However if it's a one-time password, it will insist on prompting the user,
// even though you've supplied the one-time data. This prompter is called
// to prompt the user and collect the responses. Since we can't actually 
// prompt the user, this pretends that the user typed the password, stuffing
// it in the right place for the Kerberos code. This is a stupid way to do
// things, but there doesn't seem any way to avoid Kerberos requring a prompt.

ldapsimpleprompt (krb5_context context, void *data, const char *name,
		  const char *banner, int num_prompts, krb5_prompt *prompts) {

  char *pass = (char *)data;
  if (pass && num_prompts == 1 && strncmp(prompts[0].prompt, OTPPROMPT, strlen(OTPPROMPT)) == 0 & strlen(pass) < prompts[0].reply->length) {
    strcpy(prompts[0].reply->data, pass);
    prompts[0].reply->length = strlen(pass);
    return 0;
  }
  Debug(LDAP_DEBUG_ANY, "kerbsimple_bind prompter got unknown prompt\n", 0, 0, 0);
  return -1;
}

// check a password with Kerberos.
// much of the complexity is because the password might be a one-time
// password. Sending it to the KDC has to be "armored" with a credential.
// We generate that from a key table, stuff it into a memory cache, and
// feed that cache to the password check function.

int krb_checkpassword(char *username, char *password, kerbsimple_data *kd) {

  int retval = 0;
  krb5_context context = NULL;
  krb5_principal client = NULL;
  krb5_principal armorclient = NULL;
  krb5_get_init_creds_opt *opts = NULL;
  krb5_keytab armorkeytab = NULL;
  krb5_creds usercreds;
  int haveusercreds = 0;
  krb5_creds armorcreds;
  krb5_ccache armorcache = NULL;
  int havearmorcreds = 0;
  int ok = 0;

  if ((retval = krb5_init_context(&context))) {
    Debug(LDAP_DEBUG_ANY, "kerbsimple_bind can't get krb5 context %s\n", error_message(retval), 0, 0);
    goto done;
  }

  memset(&usercreds, 0, sizeof(usercreds));
  memset(&armorcreds, 0, sizeof(armorcreds));

  // client is the principal for the actual user

  if ((retval = krb5_parse_name(context, username, &client))) {
    Debug(LDAP_DEBUG_ANY, "kerbsimple_bind can't make principal for user %s\n", error_message(retval), 0, 0);
    goto done;
  }

  // options for the login. We need to specify one option, the cache for armoring

  if ((retval = krb5_get_init_creds_opt_alloc(context, &opts))) {
    Debug(LDAP_DEBUG_ANY, "kerbsimple_bind can't get init_creds_opt %s\n", error_message(retval), 0, 0);
    goto done;
  }

  // now generate the cache for armoring, if that has been configured

  if (kd->ks_armorkeytab && kd->ks_armorprincipal) {

    // the armor is based on a key table. Find it.
    if ((retval = krb5_kt_resolve(context, kd->ks_armorkeytab, &armorkeytab))) {
      Debug(LDAP_DEBUG_ANY, "kerbsimple_bind can't get armor keytab %s\n", error_message(retval), 0, 0);
      goto done;
    }

    // principal for that key table
    if ((retval = krb5_parse_name(context, kd->ks_armorprincipal, &armorclient))) {
      Debug(LDAP_DEBUG_ANY, "kerbsimple_bind can't make principal for armor %s\n", error_message(retval), 0, 0);
      goto done;
    }

    // read the credentials from the key table
    if ((retval = krb5_get_init_creds_keytab(context, &armorcreds, armorclient, armorkeytab, 0,  NULL, NULL))) {
      Debug(LDAP_DEBUG_ANY, "kerbsimple_bind unable to make credentials from keytab %s\n", error_message(retval), 0, 0);
      goto done;
    }
    havearmorcreds = 1;
  
    // put credentials in cache for armor
    // create the cache
    if ((retval = krb5_cc_new_unique(context, "MEMORY", "xxxxxx", &armorcache))) {
      Debug(LDAP_DEBUG_ANY, "kerbsimple_bind unable to make cache %s\n", error_message(retval), 0, 0);
      goto done;
    }

    // initialize the cache with the principal
    if ((retval = krb5_cc_initialize(context, armorcache, armorclient))) {
      Debug(LDAP_DEBUG_ANY, "kerbsimple_bind unable to initialize cache %s\n", error_message(retval), 0, 0);
      goto done;
    }

    // put the credentials in the cache
    if ((retval = krb5_cc_store_cred(context, armorcache, &armorcreds))) {
      Debug(LDAP_DEBUG_ANY, "kerbsimple_bind unable to write cache %s\n", error_message(retval), 0, 0);
      goto done;
    }

    // now that we've got the cache, stick it in the option structure so the password
    // check can find it.
    if ((retval = krb5_get_init_creds_opt_set_fast_ccache(context, opts, armorcache))) {
      Debug(LDAP_DEBUG_ANY, "kerbsimple_bind can't set fast cache %s\n", error_message(retval), 0, 0);
      goto done;
    }

  }

  // do the actual password check. Get credentials for the password.
  // if the password is wrong, normally this will fail, but it's considered good practice
  // to verify that it got a valid ticket.
  if ((retval = krb5_get_init_creds_password(context, &usercreds, client, password, ldapsimpleprompt, (void *)password, 0, NULL, opts))) {
    Debug(LDAP_DEBUG_ANY, "kerbsimple_bind password wrong %s\n", error_message(retval), 0, 0);
    goto done;
  }
  haveusercreds = 1;

  // verify that the ticket we got is valid
  if ((retval = krb5_verify_init_creds(context, &usercreds, NULL, NULL, NULL, NULL))) {
    Debug(LDAP_DEBUG_ANY, "kerbsimple_bind password wrong %s\n", error_message(retval), 0, 0);
    goto done;
  }

  // OK, the Kerberos password check succeeded
  ok = 1;

 done:
  if (armorcache)
    krb5_cc_destroy(context, armorcache);
  if (haveusercreds)
    krb5_free_cred_contents(context, &usercreds);
  if (havearmorcreds)
    krb5_free_cred_contents(context, &armorcreds);
  if (opts)
    krb5_get_init_creds_opt_free(context,opts);
  if (armorkeytab)
    krb5_kt_close(context, armorkeytab);

  if (armorclient)
    krb5_free_principal(context, armorclient);
  if (client)
    krb5_free_principal(context, client);
  if (context)
    krb5_free_context(context);

  return ok;

}


// process a bind. We can return 0 to succeeed immediately,
// SLAP_CB_CONTINUE to pass the bind request to the backend LDAP
// or send an error.  If the bind request is for a DN that looks
// like uid=NNN, ..., we process it. We either return 0 or error
// except for the one administrative DN, which we pass through to the
// underlying LDAP system. For anonymous bind or binds for other
// principals, we just pass them through.

static int
kerbsimple_bind( Operation *op, SlapReply *rs )
{
  struct berval *cred = NULL;
  struct berval *dn = NULL;
  struct berval x;
  char *username;
  int ok;
  char *userstart;
  char *userend;

  // get the structure with our configuration parameters
  slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
  kerbsimple_data *kd = on->on_bi.bi_private;

  Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind\n", 0, 0, 0);

  // make sure we actually got a user and password. If not, just
  // let the backend LDAP sysetm handle it. Mostly like it's an
  // anonymous bind
  if (op->orb_cred.bv_val == NULL || op->orb_cred.bv_len == 0 ||
      op->o_req_dn.bv_val == NULL || op->o_req_dn.bv_len == 0) {
    Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind missing ptr %d cred %d\n", op->o_req_dn.bv_len, op->orb_cred.bv_len, 0);
    return SLAP_CB_CONTINUE;
  }

  Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind dn %s pass %s\n", op->o_req_dn.bv_val, op->orb_cred.bv_val, 0);

  // if the DN for the bind doesn't start with uid=, we can't
  // process it, so pass it through
  if (strncmp(op->o_req_dn.bv_val, "uid=", 4) != 0)
    return SLAP_CB_CONTINUE;

  // now isolate the username, it is between the uid= and the
  // next comma
  userstart = op->o_req_dn.bv_val + 4;
  userend = strchr(userstart, ',');
  // no comma, bad format, so pass it through
  if (!userend)
    return SLAP_CB_CONTINUE;

  username = malloc((userend - userstart) + 1);
  strncpy(username, userstart, userend-userstart);
  username[userend-userstart] = '\0';

  // do the check
  ok = krb_checkpassword(username, op->orb_cred.bv_val, kd);

  free(username);

  // this complexity is to check whether the DN is the
  // adminstrative DN. If so, we have to pass the bind to
  // the backend. THis is complicted because I want to 
  // normaize the DNs, so the comparison doesn't break
  // because of spaces or something like that. The
  // normalizer works with berval's, so we have to convert
  // what we've got to that.
  if (ok) {
    if (kd->ks_admindn) {
      int same = 0;
      int rc = 0;
      // berval form of the admin dn
      struct berval adminbv = {0, NULL};
      // bervals representing normalied versions of
      // the admin DN and my dn (the one used in this bind)
      struct berval padminbv = {0, NULL};
      struct berval pmybv = {0, NULL};
      // put the DN into the berval
      adminbv.bv_val = kd->ks_admindn;
      adminbv.bv_len = strlen(kd->ks_admindn);

      // now normalize them
      rc = dnPretty( NULL, &adminbv, &padminbv, NULL);
      if ( rc != LDAP_SUCCESS ) {
	Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind dnpretty on admindn failed\n",0, 0, 0);
	goto fail;
      }
      Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind admin pretty %s\n",padminbv.bv_val, 0, 0);

      rc = dnPretty( NULL, &op->o_req_dn, &pmybv, NULL);
      if ( rc != LDAP_SUCCESS ) {
	Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind dnpretty on my dn failed\n",0, 0, 0);
	goto fail;
      }
      Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind my pretty %s\n",pmybv.bv_val, 0, 0);

      // finally. We can compare the normalized DNs
      if (strcasecmp(padminbv.bv_val, pmybv.bv_val) == 0)
	same = 1;

    fail:
      if (padminbv.bv_val)
	ch_free(padminbv.bv_val);
      if (pmybv.bv_val)
	ch_free(pmybv.bv_val);

      Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_bind after free\n", 0, 0, 0);
      // if the DNs match, the is the administrative DN, so we
      // pass the bind to the backend
      if (same)
	return SLAP_CB_CONTINUE;
    }
    // otherwise return success. We're in the branch of code where
    // kerberos succeeded
    return 0;
  } else {
    // kerberos failed, so return an error for the bind
    Debug(LDAP_DEBUG_TRACE, "Kerberos rejected credentials", 0, 0 ,0);
    send_ldap_error( op, rs, LDAP_INVALID_CREDENTIALS,
					"Kerberos rejected credentials" );
    return rs->sr_err;
  }

}
/*
** init_module is last so the symbols resolve "for free" --
** it expects to be called automagically during dynamic module initialization
*/

// this is the main init. Done just once even if there
// are multiple instances. This is boilerplate code, the same for all
// overlays.

int
kerbsimple_initialize()
{
	int rc;

	/* statically declared just after the #includes at top */
	memset (&kerbsimple, 0, sizeof(kerbsimple));

	kerbsimple.on_bi.bi_type = "kerbsimple";
	kerbsimple.on_bi.bi_db_init = kerbsimple_db_init;
	kerbsimple.on_bi.bi_db_destroy = kerbsimple_db_destroy;
	kerbsimple.on_bi.bi_op_bind = kerbsimple_bind;

	kerbsimple.on_bi.bi_cf_ocs = kerbsimpleocs;

	Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_init\n", 0, 0, 0);

	rc = config_register_schema( kerbsimplecfg, kerbsimpleocs );

	Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_init 2 %s\n", rc, 0, 0);
	if ( rc ) return rc;

	Debug(LDAP_DEBUG_TRACE, "==> kerbsimple_init 3\n", 0, 0, 0);
	return(overlay_register(&kerbsimple));
}

int init_module(int argc, char *argv[]) {
	return kerbsimple_initialize();
}


