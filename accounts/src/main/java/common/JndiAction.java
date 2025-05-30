/*
 * Copyright 2017 by Rutgers, the State University of New Jersey
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, and
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

package common;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import javax.security.sasl.Sasl;
import org.ietf.jgss.GSSCredential;
import com.sun.security.auth.callback.TextCallbackHandler;
import org.ietf.jgss.GSSCredential;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.io.File;
import java.util.Scanner;
import Activator.Config;
	 
public class JndiAction implements java.security.PrivilegedAction<JndiAction> {
	private String[] args;
	public boolean noclose = false;
	public DirContext ctx = null;
        public GSSCredential gssapi = null;

	public ArrayList<HashMap<String,ArrayList<String>>> val = new ArrayList<HashMap<String,ArrayList<String>>>();
	// use this for new applications. The first one leads to really ugly declarations
	public List<Map<String,List<String>>> data = new ArrayList<Map<String,List<String>>>();

        public JndiAction(GSSCredential gssapio, String[] origArgs) {
	    this.gssapi = gssapio;
	    this.args = (String[])origArgs.clone();
	}

	public JndiAction run(){
	    performJndiOperation(args);
	    return null;
	}

	public static void closeCtx(DirContext ctx) {
	    try {
		ctx.close();	    
	    } catch (Exception ignore) {};
	}

	private void performJndiOperation(String[] args){

	    String filter = args[0];
	    String base = args[1];
	    Config config = Config.getConfig();

	    if (base == null || "".equals(base))
		base = config.accountbase;
	    // rest are the attrs to return
    
	    // we need to query the same LDAP server that the IPA command is going
	    // to use. Otherwise we could make a change and when the screen
	    // redisplays it may not show. If we find something configured for IPA
	    // add it to the beginning of the configuration list. That way it will
	    // be tried first but if it fails we'll fall back to the list

	    if (config.kerbldapsyncipa) {
		// only try once
		config.kerbldapsyncipa = false;
		try (var scanner = new Scanner(new File("/etc/ipa/default.conf"))) {
		    for ( ; scanner.hasNextLine() ; scanner.nextLine()) {
			// xmlrpc_uri = http(s://krb1.cs.rutgers.edu)/ipa/xml
			var item = scanner.findInLine("\\s*xmlrpc_uri\\s*=\\s*http([s*]://[^/]+)/");
			if (item == null)
			    continue;
			var url = "ldap" + scanner.match().group(1);
			// add this to the beginning of the configured url
			// but remove this url from the configured one if it's there, so we
			// don't try it twice
			config.kerbldapurl = url + " " + config.kerbldapurl.replaceAll(url + "\\s+|$", "");
			break;
		    }
		} catch (Exception e) {
		    ;
		}
	    }

	    Hashtable<String,Object> env = null;

	    if (ctx == null) {
		// Set up environment for creating initial context
		env = new Hashtable<String,Object>(11);
		
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, config.kerbldapurl);
		env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
		if (gssapi != null)
		    env.put(Sasl.CREDENTIALS, gssapi);
		env.put("com.sun.jndi.ldap.connect.pool", "true");
	    }

	    try {
		if (ctx == null)
		    ctx = new InitialDirContext(env);

		if (filter == null)
		    return;

		String[] attrIDs = new String[args.length - 2];
		for (int i = 0; i < (args.length - 2); i++) {
		    attrIDs[i] = args[i+2];
		}

		SearchControls ctls = new SearchControls();
		// if user asked for specific attributes, do so
		// otherwise he'll get them all
		if (args.length > 2)
		    ctls.setReturningAttributes(attrIDs);
		ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		NamingEnumeration answer =
		    ctx.search(base, filter, ctls);

		while (answer.hasMore()) {
		    HashMap<String,ArrayList<String>>ans = new HashMap<String,ArrayList<String>>();
		    HashMap<String,List<String>>ans2 = new HashMap<String,List<String>>();
		    val.add(ans);
		    data.add(ans2);

		    SearchResult sr = (SearchResult)answer.next();

		    // add pseudo-attribute dn
		    ArrayList<String>dns = new ArrayList<String>();
		    dns.add(sr.getNameInNamespace());
		    ans.put("dn", dns);
		    ans2.put("dn", dns);

		    Attributes attributes = sr.getAttributes();
		    NamingEnumeration attrEnum = attributes.getAll();
		    while (attrEnum.hasMore()) {
			Attribute attr = (Attribute)attrEnum.next();
			ArrayList<String>vals = new ArrayList<String>();
			NamingEnumeration valEnum = attr.getAll();
			while (valEnum.hasMore()) {
			    String s = (String)valEnum.next();
			    vals.add(s);
			}			    
			ans.put(attr.getID().toLowerCase(), vals);
			ans2.put(attr.getID().toLowerCase(), vals);
		    }
		}

	    } catch (NamingException e) {
		throw new java.lang.IllegalArgumentException("Can't get ldap data " + e);
	    } finally {
		try {
		    if (!noclose)
			ctx.close();	    
		} catch (Exception ignore) {};
	    }
	}
}





