package org.apache.guacamole.auth;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.io.PrintWriter;
import java.util.Calendar;
import java.time.LocalTime;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.net.auth.simple.SimpleUserContext;

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

    // cache ldap results. they're alway the same, so no point spaming ldap

    private static Map<String, GuacamoleConfiguration> configSave = null;
    private static LocalTime configUpdate = null;
	

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

	// on second call user is already authenticated, so ignore this
	// the caller will pass null for credentials to indicate that
	if (credentials != null) {

	    String username = credentials.getUsername();
	    String password = credentials.getPassword();

	    // for some reason we are called with nulls before the login
	    // screen is put up
	    if (username == null || password == null)
		return null;

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

	}

	// if we have cached configs within 10 minutes, use them
	// otherwise continue and get new configurations
	if (configUpdate != null && configSave != null &&
	    configUpdate.plusMinutes(10).isAfter(LocalTime.now())) {
	    return configSave;
	}

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
	    System.out.println("can't get configuration info from ldap");
	    return null;
	}

	// save new value in cache
	configSave = configs;
	configUpdate = LocalTime.now();

	return configs;

    }
    
    // just like the real one but with null credentials

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // Get configurations
        Map<String, GuacamoleConfiguration> configs =
	    getAuthorizedConfigurations(null);

        // Return as unauthorized if not authorized to retrieve configs
        if (configs == null)
            return null;

        // Return user context restricted to authorized configs
        return new SimpleUserContext(this, authenticatedUser.getIdentifier(), configs, true);

    }


}
