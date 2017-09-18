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
import java.util.Date;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.format.annotation.DateTimeFormat;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.io.*;
import java.util.Map;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import com.sun.security.auth.callback.TextCallbackHandler;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import java.util.Hashtable;
import common.JndiAction;
import common.utils;
import Activator.Config;

@Controller
public class LoginController {

    String makeCC (String user, String pass, List<String> messages) {
     
	int retval = -1;
	// create temporary cc and rename it for two reasons:
	//   want to make sure we can tell if login worked. skinit may return ok even if it fails.
	//      but if it fails it won't create the temporary cache.
	//   want to avoid race condition if there's a second process using it. atomic rename is
	//      safer than overwriting
	String tempcc = "/tmp/krb5cc_" + user + "_" + java.lang.Thread.currentThread().getId();
	String cc = "/tmp/krb5cc_" + user;
	// will rename if it succeeds
	
	String [] cmd = {"/usr/local/bin/skinit", "-l", "1d", "-c", tempcc, user};
	
	Process p = null;
	try {
	    p = Runtime.getRuntime().exec(cmd);
	} catch (Exception e) {
	    messages.add("unable to run skinit: " + e);
	}
	
	try (
	     PrintWriter writer = new PrintWriter(p.getOutputStream());
	     ) {
		writer.println(pass);
		writer.close();
		retval = p.waitFor();
		
		// we're not giving any error messages
		if (retval != 0)
		    messages.add("Bad username or password");
		
	    }
	catch(InterruptedException e2) {
	    messages.add("Password check process interrupted");
	}
	finally {
	    p.destroy();
	}
	
	// if it worked, rename cc to its real name
	// otherwise return fail.
	if (retval == 0) {
	    try {
		new File(tempcc).renameTo(new File(cc));
		return cc;
	    } catch (Exception e) {
		return null;
	    }
	} else {
	    try {
		new File(tempcc).delete();
	    } catch (Exception e) {
	    }
	    return null;
	}

   }

   // protect against unreasonable usernames

   public String filteruser(String s) {
       if (s == null)
	   return null;
       String ret = s.replaceAll("[^-_.a-z0-9]","");
       if (ret.equals(""))
	   return null;
       return ret;
   }
   public String filterpass(String s) {
       if (s == null)
	   return null;
       String ret = s.replaceAll("[\r\n]","");
       if (ret.equals(""))
	   return null;
       return ret;
   }

    class KerberosConfiguration extends Configuration { 
        private String cc;
 
        public KerberosConfiguration(String cc) { 
            this.cc = cc;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useTicketCache", "true"); 
            options.put("refreshKrb5Config", "true"); 
	    options.put("ticketCache", cc);
	    
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 




    @GetMapping("/groups/login")
    public String loginGet(HttpServletRequest request, HttpServletResponse response, Model model) {
	try {
	    if (request.getSession().getAttribute("krb5subject") != null)
		response.sendRedirect("showgroups");
	} catch (Exception e){
	}
        return "groups/login";
    }

    @PostMapping("/groups/login")
    public String loginSubmit(@RequestParam(value="user", required=false) String user,
			      @RequestParam(value="pass", required=false) String pass,
			      HttpServletRequest request, HttpServletResponse response,
			      Model model) {

	List<String>messages = new ArrayList<String>();
	model.addAttribute("messages", messages);

	LoginContext lc = null;
	String username = filteruser(user);
	String password = filterpass(pass);

	if (!username.equals(user)) {
	    messages.add("Bad username or password");
	    return loginGet(request, response, model);
	}

	// make credentials cache   

	String cc = makeCC (username, password, messages);
	if (cc == null) {
	    // should have gotten error message already
	    return loginGet(request, response, model);
	}

	// do the actuall login. Output is a Subject.

	Configuration kconfig = new KerberosConfiguration(cc);
	try {
	    lc = new LoginContext("Groups", null, null, kconfig);
	    lc.login();
	} catch (LoginException le) {
	    messages.add("Cannot create LoginContext. " + le.getMessage());
	    return loginGet(request, response, model);
	} catch (SecurityException se) {
	    messages.add("Cannot create LoginContext. " + se.getMessage());
	    return loginGet(request, response, model);
	}

	Subject subj = lc.getSubject();  
	if (subj == null) {
	    messages.add("Login failed");
	    return loginGet(request, response, model);
	}

	// the following JndAction will verify that they're in the right group,

   
	Config conf = Config.getConfig();
	String filter = conf.groupmanagerfilter.replaceAll("%u", username);

	// this action isn't actually done until it's called by doAs. That executes it for the Kerberos subject using GSSAPI
	common.JndiAction action = new common.JndiAction(new String[]{filter, "", "uid"});

	Subject.doAs(subj, action);

	// look at the result of the LDAP query. Query needs to find the user, which verifies that they're in the group
	if (action.val.size() >= 1) {
	    request.getSession().setAttribute("krb5subject", subj);
	    request.getSession().setAttribute("krb5user", username);
	    try {
		response.sendRedirect("showgroups");
	    } catch (Exception e) {
		messages.add("Unable to redirect to main application: " + e);
		return loginGet(request, response, model);
	    }
	} else {
	    messages.add("You're not authorized to manaage groups. If you should be, please send email to " + conf.helpmail + ".");
	    return loginGet(request, response, model);
	} 

	// shouldn't happen
        return "groups/login";
    }

}
