package org.apache.guacamole.auth;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.io.PrintWriter;
import java.util.Calendar;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.DirContext;
import javax.naming.NamingEnumeration;
import javax.naming.directory.SearchResult;
import javax.naming.directory.SearchControls;
import javax.naming.directory.Attributes;
import javax.naming.directory.Attribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.BasicAttribute;

/**
 * Authentication provider implementation intended to demonstrate basic use
 * of Guacamole's extension API. The credentials and connection information for
 * a single user are stored directly in guacamole.properties.
 */
public class TutorialAuthenticationProvider extends SimpleAuthenticationProvider {

    // This code gets called twice. Save the return value from
    // the first time. Without this, one-time passwords can't work,
    // because they fail the second time. It also sends the same
    // ldap search twice, which is just silly.

    // The second call removes the value, to avoid memory growth.
    private static ConcurrentHashMap<Credentials,Map<String, GuacamoleConfiguration>> authenticated = new ConcurrentHashMap<Credentials,Map<String, GuacamoleConfiguration>>();

    @Override
    public String getIdentifier() {
        return "tutorial";
    }

    @Override
    public Map<String, GuacamoleConfiguration>
	getAuthorizedConfigurations(Credentials credentials)
	throws GuacamoleException {

	// Get the Guacamole server environment
	Environment environment = new LocalEnvironment();

	
        String username = credentials.getUsername();
	String password = credentials.getPassword();

	// for some reason we are called with nulls before the login
	// screen is put up
	if (username == null || password == null)
	    return null;

	// this code gets called twice. If this is the second time, return the
	// value from the first time. Otherwise two factor won't work
	Map<String, GuacamoleConfiguration> oldvalue = authenticated.get(credentials);
	if (oldvalue != null) {
	    authenticated.remove(credentials);
	    return oldvalue;
	}

	// authenticate user, and create credential cache for xrdp to fetch
	String uuid = UUID.randomUUID().toString();
	String cc = "/var/spool/guacamole/krb5guac_" + username + "_" + uuid;
	String [] cmd = {"/usr/local/bin/skinit", "-l", "1d", "-c", cc, username};
	Process p = null;
	try {
	    p = Runtime.getRuntime().exec(cmd);
	} catch (Exception e) {
	    System.out.println("unable to run skinit: " + e);
	}

	int retval = -1;
        try (PrintWriter writer = new PrintWriter(p.getOutputStream())) {
	    writer.println(password);
	    writer.close();
	    retval = p.waitFor();
	} catch(InterruptedException e2) {
	    System.out.println("Password check process interrupted");
	} finally {
	    p.destroy();
	}	    

	if (retval != 0) {
	    credentials.setPassword("");
	    return null;
	}

	credentials.setPassword("##GUAC#" + uuid);

	// set up ldap connection to get list of hosts
	Hashtable<String, String> env = new Hashtable<String, String>();

	env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	env.put(Context.PROVIDER_URL, "ldap://krb4.cs.rutgers.edu");
	env.put(Context.SECURITY_AUTHENTICATION, "simple");
	//	env.put(Context.SECURITY_PRINCIPAL, "uid=" + username + ",cn=users,cn=accounts,dc=cs,dc=rutgers,dc=edu");
	//	env.put(Context.SECURITY_CREDENTIALS, password);
	env.put(Context.SECURITY_PRINCIPAL, "uid=ldap.admin,cn=users,cn=accounts,dc=cs,dc=rutgers,dc=edu");
	env.put(Context.SECURITY_CREDENTIALS, "abcde12345!");

	// Configurations to return
	Map<String, GuacamoleConfiguration> configs =
	    new HashMap<String, GuacamoleConfiguration>();

	DirContext context = null;
	try {
	    context = new InitialDirContext(env);

	    // search for any item with guacConfigProtocol set
	    Attributes matchAttrs = new BasicAttributes(true);
	    matchAttrs.put(new BasicAttribute("guacConfigProtocol"));

	    // loop over config items. This is the list of hosts that will appear in the menu
	    NamingEnumeration answer = context.search("cn=guac,dc=cs,dc=rutgers,dc=edu", matchAttrs);
	    while (answer.hasMore()) {

		// Create new configuration to add to the list of available hosts
		GuacamoleConfiguration config = new GuacamoleConfiguration();
		config.setProtocol("rdp");

		SearchResult sr = (SearchResult)answer.next();

		// cn is the hostname
		Attributes sa = sr.getAttributes();
		Attribute pa = sa.get("cn");
		NamingEnumeration cns = pa.getAll();		
		String hostname = (String)cns.next();

		// guacConfigParameter are parameters for this connection
		pa = sa.get("guacConfigParameter");
		NamingEnumeration params = pa.getAll();
		while (params.hasMore()) {
		    String param = (String)params.next();

		    // the value looks like name=value. Split them
		    int equals = param.indexOf('=');
		    if (equals == -1)
			throw new GuacamoleServerException("Required equals sign missing");

		    // Get name and value from parameter string
		    String name = param.substring(0, equals);
		    String value = param.substring(equals+1);

		    config.setParameter(name, value);
		}

		// add the configuration to the list. Hostname is what
		// will show in the menu
		configs.put(hostname, config);

	    }

	    GuacamoleConfiguration config = new GuacamoleConfiguration();
	    config.setProtocol("rdp");
	    config.setParameter("hostname", "geneva.cs.rutgers.edu");
	    config.setParameter("username", "${GUAC_USERNAME}");
	    config.setParameter("password", "${GUAC_PASSWORD}");
	    config.setParameter("color-depth", "24");
	    config.setParameter("ignore-cert","true");
	    
	    configs.put("-geneva", config);	    

	    context.close();
	} catch (Exception e) {
	    System.out.println("authentication failed for " + username + "/" + password + " " + e);
	    return null;
	}

	authenticated.put(credentials, configs);

	return configs;

    }
    

}
