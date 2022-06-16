package org.apache.guacamole.auth;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.io.PrintWriter;
import java.util.Calendar;
import java.time.LocalTime;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.net.auth.AbstractAuthenticatedUser;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.apache.guacamole.protocol.GuacamoleConfiguration;

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
public class TutorialAuthenticationProvider extends AbstractAuthenticationProvider {
    

    private class TutorialAuthenticatedUser extends AbstractAuthenticatedUser {

        /**
         * The credentials provided when this AuthenticatedUser was
         * authenticated.
         */
        private final Credentials credentials;

        /**
         * The GuacamoleConfigurations that this AuthenticatedUser is
         * authorized to use.
         */
        private final Map<String, GuacamoleConfiguration> configs;

	private final LocalTime creation;

        /**
         * Creates a new SimpleAuthenticatedUser associated with the given
         * credentials and having access to the given Map of
         * GuacamoleConfigurations.
         *
         * @param credentials
         *     The credentials provided by the user when they authenticated.
         *
         * @param configs
         *     A Map of all GuacamoleConfigurations for which this user has
         *     access. The keys of this Map are Strings which uniquely identify
         *     each configuration.
         */
        public TutorialAuthenticatedUser(Credentials credentials, Map<String, GuacamoleConfiguration> configs) {

            // Store credentials and configurations
            this.credentials = credentials;
            this.configs = configs;
	    this.creation = LocalTime.now();

            // Pull username from credentials if it exists
            String username = credentials.getUsername();
            if (username != null && !username.isEmpty())
                setIdentifier(username);

            // Otherwise generate a random username
            else
                setIdentifier(UUID.randomUUID().toString());

        }

        /**
         * Returns a Map containing all GuacamoleConfigurations that this user
         * is authorized to use. The keys of this Map are Strings which
         * uniquely identify each configuration.
         *
         * @return
         *     A Map of all configurations for which this user is authorized.
         */
        public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations() {
            return configs;
        }

        @Override
        public AuthenticationProvider getAuthenticationProvider() {
            return TutorialAuthenticationProvider.this;
        }

        @Override
        public Credentials getCredentials() {
            return credentials;
        }

        @Override
        public Set<String> getEffectiveUserGroups() {
            return Collections.<String>emptySet();
        }

    }

    // cache ldap results. they're alway the same, so no point spaming ldap

    private static Map<String, GuacamoleConfiguration> configSave = null;
    private static LocalTime configUpdate = null;
	

    @Override
    public String getIdentifier() {
        return "tutorial";
    }

    public AuthenticatedUser authenticateUser(final Credentials credentials)
            throws GuacamoleException {

	String username = credentials.getUsername();
	String password = credentials.getPassword();
	boolean twoFactor = false;

	// for some reason we are called with nulls before the login
	// screen is put up
	if (username == null || password == null)
	    return null;

	// authenticate user with ldap. Use the connection to see if
	// they have two factors. If so, to avoid an odd error, set
	// their password to ""

	// set up ldap connection to get list of hosts
	Hashtable<String, String> env = new Hashtable<String, String>();

	env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	env.put(Context.PROVIDER_URL, "ldap://krb4.cs.rutgers.edu");
	env.put(Context.SECURITY_AUTHENTICATION, "simple");
	env.put(Context.SECURITY_PRINCIPAL, "uid=" + username + ",cn=users,cn=accounts,dc=cs,dc=rutgers,dc=edu");
	env.put(Context.SECURITY_CREDENTIALS, password);

	// Configurations to return
	Map<String, GuacamoleConfiguration> configs =
	    new HashMap<String, GuacamoleConfiguration>();

	DirContext context = null;
	try {
	    context = new InitialDirContext(env);

	    // search for any OTP tokens owned by this person
	    Attributes matchAttrs = new BasicAttributes(true);
	    matchAttrs.put(new BasicAttribute("ipatokenOwner", "uid=" + username + ",cn=users,cn=accounts,dc=cs,dc=rutgers,dc=edu"));

	    // see if they use two factor
	    // if so clear the password. Trying to log them into the host will
	    // fail, but with a confusing screen. Better not to try. Then they
	    // get a normal login screen
	    NamingEnumeration answer = context.search("cn=otp,dc=cs,dc=rutgers,dc=edu", matchAttrs);
	    if (answer.hasMore()) {
		credentials.setPassword("");
	    }

	    // if we got here, auth worked.
	    // otherwise an exception would be thrown

	    // if we have cached configs within 10 minutes, use them
	    // otherwise continue and get new configurations
	    //	    if (configUpdate != null && configSave != null &&
	    //		configUpdate.plusMinutes(10).isAfter(LocalTime.now())) {
	    //		return new TutorialAuthenticatedUser(credentials, configSave);
	    //	    }

	    // now get the list of host configurations
	    matchAttrs = new BasicAttributes(true);
	    matchAttrs.put(new BasicAttribute("guacConfigProtocol"));

	    // loop over config items. This is the list of hosts that will appear in the menu
	    answer = context.search("cn=guac,dc=cs,dc=rutgers,dc=edu", matchAttrs);
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
	    // probably bad password
	    return null;
	}

	// save new value in cache
	configSave = configs;
	configUpdate = LocalTime.now();

	return new TutorialAuthenticatedUser(credentials, configs);

    }
    
    // just like the real one but with null credentials

    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

        // Return user context restricted to authorized configs
        return new SimpleUserContext(this, authenticatedUser.getIdentifier(),
	     ((TutorialAuthenticatedUser)authenticatedUser).getAuthorizedConfigurations(), true);

    }


}
