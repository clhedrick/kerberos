package common;
import java.util.HashSet;
import java.util.Set;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.net.InetAddress;
import common.JndiAction;
import Activator.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.TimeZone;
import java.util.Date;

public class utils {

    // in milliseconds. If password change within this of creation,
    // assume it is the random password set at account creation.
   static long FUZZ = 3000;

   static class KerberosConfiguration extends Configuration { 
        private String cc;
 
        public KerberosConfiguration(String cc) { 
            this.cc = cc;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useKeyTab", "true"); 
	    try {
		options.put("principal", "host/" + InetAddress.getLocalHost().getCanonicalHostName() + "@" + Config.getConfig().kerberosdomain); 
	    } catch (Exception e){
		System.out.println("Can't find our hostname " + e);
	    }
            options.put("refreshKrb5Config", "true"); 
	    options.put("keyTab", "/etc/krb5.keytab");
 
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 

    public static KerberosConfiguration makeKerberosConfiguration(String cc) {
	return new KerberosConfiguration(cc);
    }

    public static boolean allowChangePassword(String username) {
	Logger logger = null;
	logger = LogManager.getLogger();

	Configuration kconfig = makeKerberosConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, kconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext. " + le.getMessage());
	    return false;
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext. " + se.getMessage());
	    return false;
	}

	Subject subj = lc.getSubject();  
	if (subj == null) {
	    logger.error("Login failed");
	    return false;
	}

	JndiAction action = new JndiAction(new String[]{"(&(objectclass=inetorgperson)(uid=" + username + "))", "", "businesscategory"});
	Subject.doAs(subj, action);

	// return true only if entry exists and value is set
	// if there's no entry this is a new user, and we have
	// to be able to change their password
	if (action.val != null && action.val.size() > 0) {
	    ArrayList categories = action.val.get(0).get("businesscategory");
	    if (categories != null && categories.contains("noautopasswordchange"))
		return false;
	}

	return true;
	
    }

    public static Date parseLdapDate(String string) {
	if (string == null)
	    return null;

	if (string.endsWith("Z"))
	    string = string.substring(0, string.length()-1);

	SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
        format.setTimeZone(TimeZone.getTimeZone("UTC"));
	try {
	    return format.parse(string);
	} catch (Exception ignore) {
	    return null;
	}
    }

    public static boolean needsPassword(String username) {
	Logger logger = null;
	logger = LogManager.getLogger();

	Configuration kconfig = makeKerberosConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, kconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext. " + le.getMessage());
	    return false;
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext. " + se.getMessage());
	    return false;
	}

	Subject subj = lc.getSubject();  
	if (subj == null) {
	    logger.error("Login failed");
	    return false;
	}


	//krbLastPwdChange: 20170320203913Z
	//createTimestamp: 20170119210315Z

	JndiAction action = new JndiAction(new String[]{"(&(objectclass=inetorgperson)(uid=" + username + "))", "", "krbLastPwdChange", "createTimestamp"});
	Subject.doAs(subj, action);

	// return true only if entry exists and value is set
	// if there's no entry this is a new user, and we have
	// to be able to change their password
	if (action.val != null && action.val.size() > 0) {

	//krbLastPwdChange: 20170320203913Z
	//createTimestamp: 20170119210315Z

	    Date createDate = parseLdapDate(lu.oneVal(action.val.get(0).get("createtimestamp")));
	    Date lastChange = parseLdapDate(lu.oneVal(action.val.get(0).get("krblastpwdchange")));

	    if (createDate != null && lastChange != null) {
		long createTime = createDate.getTime();
		long lastTime = lastChange.getTime();
		// if last change near create, say we need a new password
		return (lastTime < (createTime + FUZZ));
	    }
	    // if we can't get the data, say we need a new password, for safety
	    return true;

	}

	return true;
	
    }

    public static void main( String[] argarray) {
	System.out.println(needsPassword(argarray[0]));
    }

}
