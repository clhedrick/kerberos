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
import com.sun.security.auth.callback.TextCallbackHandler;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.Map;
import java.util.List;
import java.util.Set;
import Activator.Config;
	 
public class JndiAction implements java.security.PrivilegedAction<JndiAction> {
	private String[] args;
	public boolean noclose = false;
	public DirContext ctx = null;

	public ArrayList<HashMap<String,ArrayList<String>>> val = new ArrayList<HashMap<String,ArrayList<String>>>();
	// use this for new applications. The first one leads to really ugly declarations
	public List<Map<String,List<String>>> data = new ArrayList<Map<String,List<String>>>();

	public JndiAction(String[] origArgs) {
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

	    Hashtable<String,String> env = null;

	    if (ctx == null) {
		// Set up environment for creating initial context
		env = new Hashtable<String,String>(11);
		
		env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
		env.put(Context.PROVIDER_URL, config.kerbldapurl);
		
		env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
		env.put("com.sun.jndi.ldap.connect.pool", "true");
	    }

	    try {
		if (ctx == null)
		    ctx = new InitialDirContext(env);

		String[] attrIDs = new String[args.length - 2];
		for (int i = 0; i < (args.length - 2); i++) {
		    attrIDs[i] = args[i+2];
		}

		SearchControls ctls = new SearchControls();
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
		e.printStackTrace();
	    } finally {
		try {
		    if (!noclose)
			ctx.close();	    
		} catch (Exception ignore) {};
	    }
	}
}





