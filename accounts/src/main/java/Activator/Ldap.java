package Activator;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import com.sun.security.auth.callback.TextCallbackHandler;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

	 
public class Ldap {

    public List<Map<String,List<String>>> lookup(String filter, Config config){

	    List<Map<String,List<String>>> val = new ArrayList<Map<String,List<String>>>();

	    // Set up environment for creating initial context
	    Hashtable<String,String> env = new Hashtable<String,String>(11);

	    env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	    env.put(Context.PROVIDER_URL, config.ldapurl);
	    env.put(Context.SECURITY_AUTHENTICATION, "simple");
	    env.put(Context.SECURITY_PRINCIPAL, config.ldapdn);
	    env.put(Context.SECURITY_CREDENTIALS, config.ldappass);
	    env.put("com.sun.jndi.ldap.connect.pool", "true");

	    DirContext ctx = null;

	    try {
		ctx = new InitialDirContext(env);

		SearchControls ctls = new SearchControls();
		ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

		NamingEnumeration answer =
		    ctx.search(config.ldapbase, filter, ctls);

		while (answer.hasMore()) {
		    Map<String,List<String>>ans = new HashMap<String,List<String>>();
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

	    return val;
	}
}





