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
import java.util.Set;
import Activator.Config;
	 
public class JndiAction implements java.security.PrivilegedAction<JndiAction> {
	private String[] args;
	public ArrayList<HashMap<String,ArrayList<String>>> val = new ArrayList<HashMap<String,ArrayList<String>>>();

	public JndiAction(String[] origArgs) {
	    this.args = (String[])origArgs.clone();
	}

	public JndiAction run(){
	    performJndiOperation(args);
	    return null;
	}

	private void performJndiOperation(String[] args){

	    String filter = args[0];
	    String base = args[1];
	    // rest are the attrs to return

	    // Set up environment for creating initial context
	    Hashtable<String,String> env = new Hashtable<String,String>(11);

	    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	    env.put(Context.PROVIDER_URL, Config.getConfig().kerbldapurl);

	    env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");
	    env.put("com.sun.jndi.ldap.connect.pool", "true");

	    DirContext ctx = null;

	    try {
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
		    val.add(ans);

		    SearchResult sr = (SearchResult)answer.next();
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
		    }
		}

	    } catch (NamingException e) {
		e.printStackTrace();
	    } finally {
		try {
		    ctx.close();	    
		} catch (Exception ignore) {};
	    }
	}
}





