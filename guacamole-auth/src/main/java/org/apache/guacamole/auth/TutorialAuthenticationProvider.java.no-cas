package org.apache.guacamole.auth;

import java.util.HashMap;
import java.util.Hashtable;
import java.util.Map;
import java.util.Set;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.io.*;
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
import org.apache.guacamole.net.auth.credentials.GuacamoleInvalidCredentialsException;
import org.apache.guacamole.net.auth.credentials.CredentialsInfo;

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
    
    private Map<String, GuacamoleConfiguration> globalconfigs;

    // cache ldap results. they're alway the same, so no point spaming ldap

    private static Map<String, GuacamoleConfiguration> configSave = null;
    private static LocalTime configUpdate = null;
	

    @Override
    public String getIdentifier() {
        return "tutorial";
    }
    
    // not currently doing this
    // if we have cached configs within 10 minutes, use them
    // otherwise continue and get new configurations
    //      if (configUpdate != null && configSave != null &&
    //          configUpdate.plusMinutes(10).isAfter(LocalTime.now())) {
    //          return new TutorialAuthenticatedUser(credentials, configSave);
    //      }

    // cas is going to do the auth

    private class TutorialAuthenticatedUser extends AbstractAuthenticatedUser {

        /**
         * The credentials provided when this AuthenticatedUser was
         * authenticated.
         */
        private final Credentials credentials;

	/*
         * Creates a new SimpleAuthenticatedUser associated with the given
         * credentials and having access to the given Map of
         * GuacamoleConfigurations.
         *
         * @param credentials
         *     The credentials provided by the user when they authenticated.
         *
         */
        public TutorialAuthenticatedUser(Credentials credentials) {

            // Store credentials and configurations
            this.credentials = credentials;

            // Pull username from credentials if it exists
            String username = credentials.getUsername();
            if (username != null && !username.isEmpty())
                setIdentifier(username);

            // Otherwise generate a random username
            else
                setIdentifier(UUID.randomUUID().toString());

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


    public AuthenticatedUser authenticateUser(final Credentials credentials)
            throws GuacamoleException {

	String username = credentials.getUsername();
	String password = credentials.getPassword();
	boolean twoFactor = false;

	if (username == null || password == null)
	    return null;

	String [] cmd = {"/usr/libexec/checkpass", username};

	try {
            Process p = Runtime.getRuntime().exec(cmd);
	    try (PrintWriter writer = new PrintWriter(p.getOutputStream());
		 BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
		 BufferedReader reader2 = new BufferedReader(new InputStreamReader(p.getErrorStream()))) {
		writer.println(password);
		writer.flush();
                writer.close();
		if (false) {
		    String line=reader.readLine();
		    while (line != null) {
			System.out.println(line);
			line = reader.readLine();
		    }
		    line=reader2.readLine();
		    while (line != null) {
			System.out.println(line);
			line = reader2.readLine();
		    }
		}

                int retval = p.waitFor();
                if (retval != 0) {
		    System.out.println("login failed for " + username + " " + retval);
		    return null;
		}
		System.out.println("login ok for " + username);
	    }
	} catch (Exception e) {
	    System.out.println("Exception " + e);
	}

	return new TutorialAuthenticatedUser(credentials);

    }


    @Override
    public UserContext getUserContext(AuthenticatedUser authenticatedUser)
            throws GuacamoleException {

	if (configUpdate != null && configSave != null &&
	    configUpdate.plusMinutes(10).isAfter(LocalTime.now())) {
	    System.out.println("returning saved config");
	    return new SimpleUserContext(this, authenticatedUser.getIdentifier(), configSave, true);
	}

	Environment environment = LocalEnvironment.getInstance();

        String username = authenticatedUser.getCredentials().getUsername();

	//        System.out.println("tutoral getusercontext");
	
	// set up ldap connection to get list of hosts
	Hashtable<String, String> env = new Hashtable<String, String>();

	String provider_url = environment.getRequiredProperty(
	    TutorialGuacamoleProperties.PROVIDER_URL
        );   

	//	System.out.println("tutoral url " + provider_url);
	
	String search_dn = environment.getRequiredProperty(
	    TutorialGuacamoleProperties.SEARCH_DN
        );   

	//	System.out.println("tutoral dn " + search_dn);
	
	String search_password = environment.getRequiredProperty(
	    TutorialGuacamoleProperties.SEARCH_PASSWORD
        );   

	//	System.out.println("tutoral password " + search_password);
	
	String allowed_group = environment.getRequiredProperty(
	    TutorialGuacamoleProperties.ALLOWED_GROUP
        );   

	String user_base = environment.getRequiredProperty(
	    TutorialGuacamoleProperties.USER_BASE
        );   

	String guac_data = environment.getRequiredProperty(
	    TutorialGuacamoleProperties.GUAC_DATA
        );   


	env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	env.put(Context.PROVIDER_URL, provider_url);
	env.put(Context.SECURITY_AUTHENTICATION, "simple");
	env.put(Context.SECURITY_PRINCIPAL, search_dn);
	env.put(Context.SECURITY_CREDENTIALS, search_password);

	// Configurations to return
	Map<String, GuacamoleConfiguration> configs =
	    new HashMap<String, GuacamoleConfiguration>();

	DirContext context = null;
	boolean ok = false;
	try {
	    context = new InitialDirContext(env);

	    // see if the user is in login-ilab
	    Attributes matchAttrs = new BasicAttributes(true);

	    matchAttrs.put(new BasicAttribute("memberOf"));
	    matchAttrs.put(new BasicAttribute("cn"));	    

	    Attributes ans = context.getAttributes("uid=" + username + "," + user_base);

	    for (NamingEnumeration ae = ans.getAll(); ae.hasMore();) {
		Attribute attr = (Attribute)ae.next();
		if (attr.getID().equals("memberOf")) {
		    for (NamingEnumeration e = attr.getAll(); e.hasMore();)
			if (e.next().toString().equals(allowed_group))
			    ok = true;
		}
	    }

	    if (! ok)  {
		context.close();
		System.out.println("user " + username + " logged in but no CS account");
		throw new GuacamoleInvalidCredentialsException("Password OK, but you don't have an active CS account.",
							       CredentialsInfo.USERNAME_PASSWORD);
	    }
	    //	    System.out.println("tutoral getconfig");

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
	    NamingEnumeration answer = context.search(guac_data, matchAttrs);
	    while (answer.hasMore()) {
		//		System.out.println("tutoral item");

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

	    configSave = configs;
	    configUpdate = LocalTime.now();

	} catch (GuacamoleInvalidCredentialsException e) {
	    // rethrow
	    throw new GuacamoleInvalidCredentialsException("Invalid login.",
							   CredentialsInfo.USERNAME_PASSWORD);
	} catch (Exception e) {
	}
	System.out.println("returning new config");

        // Return user context restricted to authorized configs
	return new SimpleUserContext(this, authenticatedUser.getIdentifier(), configs, true);

    }


}
