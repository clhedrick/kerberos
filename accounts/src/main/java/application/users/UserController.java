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

package application;

import java.util.List;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.text.SimpleDateFormat;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import javax.security.auth.kerberos.KerberosTicket;
import com.sun.security.auth.callback.TextCallbackHandler;
import java.util.Hashtable;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.StringEscapeUtils;
import java.net.URLEncoder;
import common.lu;
import common.utils;
import common.JndiAction;
import common.docommand;
import Activator.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Controller
public class UserController {

    @Autowired
    private LoginController loginController;

    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^-_.a-z0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    class ServicesConfiguration extends Configuration { 
        private String cc;
 
        public ServicesConfiguration(String cc) { 
            this.cc = cc;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useKeyTab", "true"); 
	    options.put("principal", "http/services.cs.rutgers.edu@" + Config.getConfig().kerberosdomain); 
            options.put("refreshKrb5Config", "true"); 
	    options.put("keyTab", "/etc/krb5.keytab.services");
 
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 

    public ServicesConfiguration makeServicesConfiguration(String cc) {
	return new ServicesConfiguration(cc);
    }

    public String showError(String message, HttpServletRequest request, HttpServletResponse response, Model model) {
	List<String> messages = new ArrayList<String>();
	messages.add("Session has expired");
	model.addAttribute("messages", messages);
	return loginController.loginGet("user", request, response, model); 
    }

    // show info for current user
    @GetMapping("/users/showuser")
    public String userGet(HttpServletRequest request, HttpServletResponse response, Model model) {

	Logger logger = null;
	logger = LogManager.getLogger();

	String user = (String)request.getSession().getAttribute("krb5user");

	Subject userSubject = (Subject)request.getSession().getAttribute("krb5subject");
	if (userSubject == null) {
	    List<String> messages = new ArrayList<String>();
	    messages.add("Session has expired");
	    model.addAttribute("messages", messages);
	    return loginController.loginGet("user", request, response, model); 
	}

	Configuration sconfig = makeServicesConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, sconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext for services. " + le.getMessage());
	    return showError("Cannot create LoginContext for services. " + le.getMessage(), request, response, model);
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext for services. " + se.getMessage());
	    return showError("Cannot create LoginContext for services. " + se.getMessage(), request, response, model);
	}

	Subject servicesSubject = lc.getSubject();  
	if (servicesSubject == null) {
	    logger.error("Cannot login for services.");
	    return showError("Cannot login for services.", request, response, model);
	}

	DirContext ctx = null;
	try {

	    // This acton isn't done until it's called by doAs
	    //ipatokenRadiusUserName: hedrick
	    //ipatokenRadiusConfigLink: cn=ldap-proxy,cn=radiusproxy,dc=cs,dc=rutgers,dc=edu

	    common.JndiAction action = new common.JndiAction(new String[]{"(uid=" + user + ")", "", "cn", "ipatokenradiusconfiglink", "ipatokenradiususername", "dn", "businesscategory"});
	    action.noclose = true; // hold context for reuse

	    Subject.doAs(servicesSubject, action);
	    ctx = action.ctx; // get the context so we can use it for other operations

	    if (action.val.size() != 1) {
		List<String> messages = new ArrayList<String>();
		return showError("User not found.", request, response, model);
	    }

	    HashMap<String, ArrayList<String>> attrs = null;
	    attrs = action.val.get(0);
	    
	    String username = lu.oneVal(attrs.get("cn"));
	    String dn = lu.oneVal(attrs.get("dn"));
	    String radiustype = null;
	    String radiususer = null;
	    boolean passwordChange = true;
	    String authtype = "system";
	    String authtext = null;
	    String note = null;
	    boolean university = false;
	    
	    radiustype = lu.oneVal(attrs.get("ipatokenradiusconfiglink"));
	    if (radiustype != null) {
		int i = radiustype.indexOf(",");
		if (i > 0)
		    radiustype = radiustype.substring(0, i);
		if (radiustype.startsWith("cn="))
		    radiustype = radiustype.substring(3);
		radiususer = lu.oneVal(attrs.get("ipatokenradiususername"), "");
	    }

	    if (radiustype != null) {
		if (radiustype.equals(Config.getConfig().universityradius)) {
		    authtext = "University password for user " + radiususer;
		    authtype = "university";
		    university = true;
		} else {
		    authtext = "radius password using proxy " + radiustype + " and user " + radiususer;
		    authtype = "unknown";
		}
	    }

	    ArrayList categories = attrs.get("businesscategory");
	    if (categories != null && categories.contains("noautopasswordchange"))
		passwordChange = false;

	    String otptokens = "";

	    action = new common.JndiAction(new String[]{"(ipatokenOwner=" + dn + ")", "cn=otp,dc=cs,dc=rutgers,dc=edu", "cn", "ipatokenuniqueid", "objectclass"});

	    action.noclose = true; // hold context for reuse
	    action.ctx = ctx; // reuse existing context

	    Subject.doAs(servicesSubject, action);

	    if (authtext == null) {
		if (action.val.size() > 0) {
		    authtext = Config.getConfig().systemname + " one-time password";
		    authtype = "otp";
		    if (passwordChange)
			note = "The unchanging part of your password may be changed using the \"Set or reset password\" link here, using your University password.";
		    else
			note = "The unchanging part of your password may be changed using the \"kpasswd\" command on any of our systems. If you have forgotten it, please contact staff to change it for you.";
		} else {
		    authtext = Config.getConfig().systemname + " password";
		    if (passwordChange)
			note = "Your password may be changed using the \"Set or reset password\" link here, using your University password.";
		    else
			note = "Your password may be changed using the \"kpasswd\" command on any of our systems. If you have forgotten it, please contact staff to change it for you.";
		}
	    } else {
		note = "Your password may be changed at https://netid.rutgers.edu";
	    }

	    model.addAttribute("username", username);
	    model.addAttribute("user", user);
	    model.addAttribute("authtext", authtext);
	    model.addAttribute("authtype", authtype);
	    model.addAttribute("note", note);
	    model.addAttribute("university", university);
	    model.addAttribute("passwordchange", passwordChange);

	    return "users/showuser";

	} catch (Exception e) {
	    logger.error("Exception in userGet. " + e.getMessage());
	    return showError("Can't get information about you. " + e.getMessage(), request, response, model);
	} finally {
	    // we used noclose for all JndiActions, so we wouldn't get new connections for each user lookup
	    // so we have to close it explicitly
	    if (ctx != null)
		JndiAction.closeCtx(ctx);
	}

    }

    @PostMapping("/users/showuser")
    public String userSubmit(@RequestParam(value="university", required=false) boolean university,
			     @RequestParam(value="passwordchange", required=false) boolean passwordChange,
			     HttpServletRequest request, HttpServletResponse response,
			     Model model) {

	Logger logger = null;
	logger = LogManager.getLogger();

	String user = (String)request.getSession().getAttribute("krb5user");

	Configuration sconfig = makeServicesConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, sconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext for services. " + le.getMessage());
	    return showError("Cannot create LoginContext for services. " + le.getMessage(), request, response, model);
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext for services. " + se.getMessage());
	    return showError("Cannot create LoginContext for services. " + se.getMessage(), request, response, model);
	}

	Subject servicesSubject = lc.getSubject();  
	if (servicesSubject == null) {
	    logger.error("Cannot login for services.");
	    return showError("Cannot login for services.", request, response, model);
	}

	common.JndiAction action = new common.JndiAction(new String[]{"(uid=" + user + ")", "", "cn", "ipatokenradiusconfiglink", "ipatokenradiususername", "dn", "businesscategory"});

	Subject.doAs(servicesSubject, action);

	if (action.val == null || action.val.size() == 0) {
	    List<String> messages = new ArrayList<String>();
	    messages.add("Unable to find user");
	    model.addAttribute("messages", messages);
	    return userGet(request, response, model); 
	}

	HashMap<String, ArrayList<String>> attrs = null;
	attrs = action.val.get(0);

	String radiustype = null;
	boolean oldUniversity = false;
	boolean oldPasswordChange = true;

	radiustype = lu.oneVal(attrs.get("ipatokenradiusconfiglink"));
	if (radiustype != null) {
	    int i = radiustype.indexOf(",");
	    if (i > 0)
		radiustype = radiustype.substring(0, i);
	    if (radiustype.startsWith("cn="))
		radiustype = radiustype.substring(3);
	    if (radiustype != null && radiustype.equals(Config.getConfig().universityradius)) {
		oldUniversity = true;
	    }
	}


	ArrayList categories = attrs.get("businesscategory");
	if (categories != null && categories.contains("noautopasswordchange"))
	    oldPasswordChange = false;

	String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/user/bin"};

	if (!oldUniversity && university) {
	    logger.info("ipa user-mod " + user + " --radius=" + Config.getConfig().universityradius);
	    if (docommand.docommand (new String[]{"/bin/ipa", "user-mod", user, "--radius=" + Config.getConfig().universityradius}, env) != 0) {
		List<String> messages = new ArrayList<String>();
		messages.add("Unable to set up for University password");
		model.addAttribute("messages", messages);
		return userGet(request, response, model); 
	    }

	}

	if (oldUniversity && !university) {
	    logger.info("ipa user-mod " + user + " --radius=");
	    if (docommand.docommand (new String[]{"/bin/ipa", "user-mod", user, "--radius="}, env) != 0) {
		List<String> messages = new ArrayList<String>();
		messages.add("Unable to remove setting for University password");
		model.addAttribute("messages", messages);
		return userGet(request, response, model); 
	    }
	    
	}

	if (!oldPasswordChange && passwordChange) {
	    logger.info("ipa user-mod " + user + " --delattr=businesscategory=noautopasswordchange");
	    if (docommand.docommand (new String[]{"/bin/ipa", "user-mod", user, "--delattr=businesscategory=noautopasswordchange"}, env) != 0) {
		List<String> messages = new ArrayList<String>();
		messages.add("Unable to enable password change");
		model.addAttribute("messages", messages);
		return userGet(request, response, model); 
	    }
	}

	if (oldPasswordChange && !passwordChange) {
	    logger.info("ipa user-mod " + user + " --addattr=businesscategory=noautopasswordchange");
	    if (docommand.docommand (new String[]{"/bin/ipa", "user-mod", user, "--addattr=businesscategory=noautopasswordchange"}, env) != 0) {
		List<String> messages = new ArrayList<String>();
		messages.add("Unable to disable password change");
		model.addAttribute("messages", messages);
		return userGet(request, response, model); 
	    }
	}

	return loginController.loginGet("user", request, response, model); 

    }

}
