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
import java.util.HashSet;
import java.util.Set;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.Calendar;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.text.SimpleDateFormat;
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
import jakarta.servlet.http.HttpServletRequest;
import java.util.Random;

public class utils {

    public static class PasswordInfo {
	public boolean allowChangePassword;
	public boolean universityPassword;
    }


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
		options.put("principal", "HTTP/" + InetAddress.getLocalHost().getCanonicalHostName() + "@" + Config.getConfig().kerberosdomain); 
	    } catch (Exception e){
		System.out.println("Can't find our hostname " + e);
	    }
            options.put("refreshKrb5Config", "true"); 
	    options.put("keyTab", "/etc/krb5.keytab.http");
 
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 

    public static KerberosConfiguration makeKerberosConfiguration(String cc) {
	return new KerberosConfiguration(cc);
    }

    // normally we allow people to set a new password after logging in
    // with their University password. This saves us from havin to deal with
    // forgotten passwords. However it means that if someone cracks the University
    // password they can set ours. Some users may want to disable this, so that 
    // their password in our system can be more secure than the University password.
    // For those users we set businessCategory=noautopasswordchange
    // This routine checks for that attribute.

    public static PasswordInfo getPasswordInfo(String username) {
	Logger logger = null;
	logger = LogManager.getLogger();

	// give us a kerberos configuration that users /etc/krb5.keytab for authentication
	Configuration kconfig = makeKerberosConfiguration(null);
	// authenticate. creates a Kerberos credentials cache internally
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, kconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext. " + le.getMessage());
	    return null;
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext. " + se.getMessage());
	    return null;
	}

	// Subject is Java's internal version of a credentials cache
	Subject subj = lc.getSubject();  
	if (subj == null) {
	    logger.error("Login failed");
	    return null;
	}

	// Create the ldap query.
	JndiAction action = new JndiAction(null, new String[]{"(&(objectclass=inetorgperson)(uid=" + username
	    + "))", "", "businesscategory", "ipatokenradiusconfiglink"});
	// execute the query authenticated with our Kerberos credentials
	Subject.doAs(subj, action);

	// return true only if entry exists and value is set
	// if there's no entry this is a new user, and we have
	// to be able to change their password
	if (action.val != null && action.val.size() > 0) {
	    var passwordInfo = new PasswordInfo();

	    ArrayList categories = action.val.get(0).get("businesscategory");
	    passwordInfo.allowChangePassword = (categories == null || ! categories.contains("noautopasswordchange"));

	    var radiusconfig = action.val.get(0).get("ipatokenradiusconfiglink");
	    passwordInfo.universityPassword = (radiusconfig != null && radiusconfig.contains("cn=univ-password,cn=radiusproxy,dc=cs,dc=rutgers,dc=edu"));

	    return passwordInfo;

	}

	return null;
	
    }

    // take a date/time in the format used by LDAP and return a
    // Java Date.
    public static Date parseLdapDate(String string) {
	if (string == null)
	    return null;

	// normally the time ends in Z. SimpleDateFormat can't handle that, so remove it
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

    // when a user activates on a system we create the user entry if
    // we haven't seen them before. The entry is created with a random
    // password. They need to create their own. This indicates whether
    // the user needs to create a password. If so, we send them to the
    // password change screen.
    public static boolean needsPassword(String username) {
	Logger logger = null;
	logger = LogManager.getLogger();

	// give us a kerberos configuration that users /etc/krb5.keytab for authentication
	Configuration kconfig = makeKerberosConfiguration(null);
	// authenticate. creates a Kerberos credentials cache internally
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

	// Subject is Java's internal version of a credentials cache
	Subject subj = lc.getSubject();  
	if (subj == null) {
	    logger.error("Login failed");
	    return false;
	}


	//krbLastPwdChange: 20170320203913Z
	//createTimestamp: 20170119210315Z

	// Create the ldap query.
	JndiAction action = new JndiAction(null, new String[]{"(&(objectclass=inetorgperson)(uid=" + username + "))", "", "krbLastPwdChange", "createTimestamp", "ipatokenradiusconfiglink"});
	// execute the query authenticated with our Kerberos credentials
	Subject.doAs(subj, action);

	// return true only if entry exists and value is set
	// if there's no entry this is a new user, and we have
	// to be able to change their password
	if (action.val != null && action.val.size() > 0) {

	    // if using radius we don't need to set a password
	    var radiuslink = lu.oneVal(action.val.get(0).get("ipatokenradiusconfiglink"));
	    if (radiuslink != null)
		return false;

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

    static Random random = new Random();

    public static String getCsrfToken(HttpServletRequest request) {
	String csrf = (String)request.getSession().getAttribute("csrftoken");
	if (csrf == null) {
	    csrf = Long.toUnsignedString(random.nextLong()) + Long.toUnsignedString(random.nextLong());
	    request.getSession().setAttribute("csrftoken", csrf);	    
	}
	return csrf;
    }

    public static String getCsrf(HttpServletRequest request) {
	return "<input type=\"hidden\" name=\"csrftoken\" value=\"" + getCsrfToken(request) + "\"/>";
    }

    public static void checkCsrf(HttpServletRequest request) {
	String token = request.getParameter("csrftoken");
	String csrf = getCsrfToken(request);
	if (csrf.equals(token))
	    return;
	throw new java.lang.IllegalArgumentException("no permission");
    }

    public static boolean needsReview(Map<String, List<String>>attrs) {
	// silly to ask for a review if there are no members
	// yeah, but the logic gets complex. what if they create a group and add
	// a member a year - a day later. they'll get an immediate review
	//if (!lu.hasVal(attrs.get("member")))
	//	    return false;

	String reviewtime = Config.getConfig().reviewtime;
	// default is no review
	if (reviewtime == null)
	    return false;

	Integer reviewDays = Integer.parseInt(reviewtime);

	// only review login groups
	if (! lu.valList(attrs.get("businesscategory")).contains("login"))
	    return false;

	SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
	format.setTimeZone(TimeZone.getTimeZone("UTC"));

	String created = null;
	if (attrs.get("dateofcreate") != null)
	    created = attrs.get("dateofcreate").get(0);
	else
	    created = attrs.get("createtimestamp").get(0);

	try {
	    Date createdDate = format.parse(created);
	    Calendar reviewdate = Calendar. getInstance();
	    reviewdate.setTime(createdDate);
	    reviewdate.add(Calendar.DATE, reviewDays);
	    Calendar now = Calendar. getInstance();
	    if (now.after(reviewdate))
		return true;
	} catch (Exception ignore) {}

	return false;
    }

    // find the first match in a regexp. THis would be the first
    // thing in (). Uses find, so you need to put ^ at the beginning
    // and $ at the end if you want to match the whole string
    public static String getMatch(String input, String regex) {
	Pattern pat = Pattern.compile(regex);
	if (pat == null)
	    return null;
	Matcher matcher = pat.matcher(input);
	if (matcher == null)
	    return null;
	if (!matcher.find())
	    return null;
	return matcher.group(1);
    }

    public static void main( String[] argarray) {
	String memberhost = getMatch(argarray[0], "^fqdn=(.+?),");
	System.out.println(memberhost);
	//	System.out.println(needsPassword(argarray[0]));
    }

}
