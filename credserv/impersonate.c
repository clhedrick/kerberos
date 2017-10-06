/* $Id: k5tgp.c,v 1.9 2006/04/09 00:24:40 zacheiss Exp zacheiss $ */

/* permission to use for this project given by email, Oct 5, 2017 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <krb5.h>
#include <com_err.h>
#include <syslog.h>

#include "credldap.h"

char *whoami;
krb5_data empty_string = {0, 0, ""};

extern int debug;

#define DEFAULT_LIFETIME (60 * 60 * 24)
#define DEFAULT_RENEWTIME (60 * 60 * 24 * 365)

// need to route com_err through mylog
#define com_err(whoami, code, str)  mylog(LOG_ERR, str"%s", error_message(code))

/* Prototypes from k5-int.h */
krb5_error_code encode_krb5_ticket(const krb5_ticket *, krb5_data **);
krb5_error_code krb5_encrypt_tkt_part(krb5_context, const krb5_keyblock *,
				      krb5_ticket * );
int impersonate(krb5_context context, krb5_principal client, char *realm, krb5_ccache ccache, char *ktname);

int impersonate(krb5_context context, krb5_principal client, char *realm, krb5_ccache ccache, char *ktname) {
  char *pname = NULL;
  char *unparsed_service = NULL, *unparsed_principal = NULL;
  char buf[BUFSIZ];
  krb5_ticket ticket;
  krb5_enc_tkt_part enc_tkt;
  krb5_keyblock session_key, server_key;
  krb5_principal server = NULL;
  krb5_error_code code;
  krb5_timestamp now;
  krb5_timestamp lifetime = DEFAULT_LIFETIME;
  krb5_timestamp renewtime = DEFAULT_RENEWTIME;
  krb5_kvno kvno = 0;
  krb5_creds creds;
  // int creds_keyblock_alloc = 0;
  krb5_data *packet = NULL;
  krb5_keytab kt = NULL;
  krb5_keytab_entry entry;
  krb5_kt_cursor cursor;
  int inseq = 0;
  krb5_address **addresses = NULL;

  session_key.contents = 0;
  server_key.contents = 0;

  whoami = "credserv";

  code = krb5_timeofday(context, &now);
  if (code)
    {
      com_err(whoami, code, "in krb5_timeofday");
      goto out;
    }

  // make krbtgt/CS.RUTGERS.EDU@CS.RUTGERS.EDU
  if ((code = krb5_build_principal(context, &server, strlen(realm), realm, "krbtgt", realm, NULL))) {
    com_err(whoami, code, "unable to make principal for tgt");
    goto out;
  }    

  code = krb5_unparse_name(context, server, &unparsed_service);
  if (code)
    {
      com_err(whoami, code, "in krb5_unparse_name of server");
      goto out;
    }

  // client is user@REALM, cc is passed in
  code = krb5_unparse_name(context, client, &unparsed_principal);
  if (code)
    {
      com_err(whoami, code, "in krb5_unparse_name of client");
      goto out;
    }

  code = krb5_kt_resolve(context, ktname, &kt);
  if (code)
    {
      com_err(whoami, code, "in krb5_kt_resolve");
      goto out;
    }

  code = krb5_kt_get_name(context, kt, buf, BUFSIZ);
  if (code)
    {
      com_err(whoami, code, "in krb5_kt_get_name");
      goto out;
    }
  
  if (debug)
    mylog(LOG_DEBUG, "Using keytab %s", buf);
      
  code = krb5_kt_start_seq_get(context, kt, &cursor);
  if (code)
    {
      com_err(whoami, code, "in krb5_kt_start_seq_get");
      goto out;
    }
  
  inseq = 1;
  while ((code = krb5_kt_next_entry(context, kt, &entry, &cursor)) == 0)
    {
      code = krb5_unparse_name(context, entry.principal, &pname);
      if (code)
	{
	  krb5_kt_free_entry(context, &entry);
	  com_err(whoami, code, "in krb5_unparse_name");
	  goto out;
	}
      
      if ((strcmp(unparsed_service, pname)) != 0)
	{
	  krb5_kt_free_entry(context, &entry);
	  if (debug)
	    mylog(LOG_DEBUG, "Skipping entry for principal %s", pname);
	  continue;
	}
      
      /* Find the latest kvno */
      if (entry.vno > kvno)
	{
	  if (server_key.contents)
	    {
	      krb5_free_keyblock_contents(context, &server_key);
	      server_key.contents = 0;
	    }
	  
	  kvno = entry.vno;
	  code = krb5_copy_keyblock_contents(context, &entry.key,
					     &server_key);
	  if (code)
	    {
	      krb5_kt_free_entry(context, &entry);
	      com_err(whoami, code,
		      "in krb5_copy_keyblock_contents of server_key");
	      goto out;
	    }
	}
      krb5_free_unparsed_name(context, pname);
      pname = NULL;
      krb5_kt_free_entry(context, &entry);
    }
  
  if (code && code != KRB5_KT_END)
    {
      com_err(whoami, code, "in krb5_kt_next_entry");
      goto out;
    }
  
  code = krb5_kt_end_seq_get(context, kt, &cursor);
  if (code)
    {
      com_err(whoami, code, "in krb5_kt_end_seq_get");
      goto out;
    }
  inseq = 0;
  
  if (kvno == 0)
    {
      /* We didn't find a matching entry in the keytab, punt. */
      mylog(LOG_ERR, "No entries for service %s in keytab %s.",
	      unparsed_service, buf);
      return 1;
    }

  code = krb5_c_make_random_key(context, server_key.enctype, &session_key);
  if (code)
    {
      com_err(whoami, code, "in krb5_c_make_random_key");
      goto out;
    }

  enc_tkt.magic = KV5M_ENC_TKT_PART;
  enc_tkt.flags = TKT_FLG_FORWARDABLE | TKT_FLG_RENEWABLE | TKT_FLG_INITIAL | TKT_FLG_PRE_AUTH;

  enc_tkt.session = &session_key;
  enc_tkt.client = client;
  enc_tkt.transited.tr_type = KRB5_DOMAIN_X500_COMPRESS;
  enc_tkt.transited.tr_contents = empty_string;
  enc_tkt.times.authtime = now;
  enc_tkt.times.starttime = now;
  enc_tkt.times.endtime = now + lifetime;
  enc_tkt.times.renew_till = now + renewtime;
  enc_tkt.authorization_data = 0;

  if ((code =krb5_os_localaddr(context, &addresses))) {
    com_err(whoami, code, "getting addresses");
    goto out;
  }
  enc_tkt.caddrs = addresses;

  memset((char *) &ticket, 0, sizeof(ticket));

  ticket.magic = KV5M_TICKET;
  ticket.enc_part2 = &enc_tkt;
  ticket.server = server;

  code = krb5_encrypt_tkt_part(context, &server_key, &ticket);
  if (code)
    {
      com_err(whoami, code, "in krb5_encrypt_tkt_part");
      goto out;
    }

  ticket.enc_part.kvno = kvno;

  mylog(LOG_DEBUG, "Creating %s service ticket for principal %s, kvno %d.",
	unparsed_service, unparsed_principal, kvno);

  memset((char *) &creds, 0, sizeof(creds));

  creds.magic = KV5M_CREDS;

  code = krb5_copy_principal(context, client, &creds.client);
  if (code)
    {
      com_err(whoami, code, "in krb5_copy_principal of client");
      goto out;
    }

  code = krb5_copy_principal(context, server, &creds.server);
  if (code)
    {
      com_err(whoami, code, "in krb5_copy_principal of server");
      goto out;
    }

  code = krb5_copy_keyblock_contents(context, &session_key,
				     &creds.keyblock);
  if (code)
    {
      com_err(whoami, code, "in krb5_copy_keyblock_contents");
      goto out;
    }

  //  creds_keyblock_alloc = 1;
  creds.times = ticket.enc_part2->times;
  creds.is_skey = FALSE;
  creds.ticket_flags = ticket.enc_part2->flags;
  creds.addresses = addresses;
  creds.second_ticket.length = 0;
  creds.second_ticket.data = 0;
  creds.authdata = NULL;

  code = encode_krb5_ticket(&ticket, &packet);
  if (code)
    {
      com_err(whoami, code, "in encode_krb5_ticket");
      goto out;
    }

  creds.ticket = *packet;

  code = krb5_cc_initialize(context, ccache, client);
  if (code)
    {
      com_err(whoami, code, "in krb5_cc_initialize");
      goto out;
    }
  
  code = krb5_cc_store_cred(context, ccache, &creds);
  if (code)
    {
      com_err(whoami, code, "in krb5_cc_store_cred");
      goto out;
    }

 out:
  // this is in a subfork that will exit quickly. 
  // sort of silly to do frees, so only do things that close files

  //  if (addresses)
  //    krb5_free_addresses(context, addresses);
  //  if (ticket.enc_part.ciphertext.data)
  //    free(ticket.enc_part.ciphertext.data);
  if (inseq)
    krb5_kt_end_seq_get(context, kt, &cursor);
  if (kt)
    krb5_kt_close(context, kt);
  //  if (creds_keyblock_alloc)
  //    krb5_free_keyblock_contents(context, &creds.keyblock);
  //  if (creds.server)
  //    krb5_free_principal(context, creds.server);
  //  if (creds.client)
  //    krb5_free_principal(context, creds.client);
  //  if (packet)
  //    krb5_free_data(context, packet);
  //  if (server)
  //    krb5_free_principal(context, server);
  //  if (session_key.contents)
  //    krb5_free_keyblock_contents(context, &session_key);
  //  if (server_key.contents && !useafskeyfile)
  //    krb5_free_keyblock_contents(context, &server_key);
  //  if (ccache)
  //    krb5_cc_close(context, ccache);
  //  if (pname)
  //    krb5_free_unparsed_name(context, pname);
  //  if (unparsed_service)
  //    krb5_free_unparsed_name(context, unparsed_service);
  //  if (unparsed_principal)
  //    krb5_free_unparsed_name(context, unparsed_principal);

  if (code)
    return 1;
  else
    return 0;
}

