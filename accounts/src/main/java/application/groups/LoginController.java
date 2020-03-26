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

import java.security.PrivilegedExceptionAction;
import java.security.PrivilegedActionException;
import com.sun.security.auth.module.Krb5LoginModule;
import org.springframework.security.authentication.BadCredentialsException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import java.net.InetAddress;
import com.sun.security.jgss.GSSUtil;
import com.sun.security.jgss.ExtendedGSSContext;
import org.ietf.jgss.Oid;
import java.util.Base64;
import java.util.List;
import java.util.Date;
import java.util.Collection;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.http.HttpStatus;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.Set;
import java.util.HashSet;
import com.sun.security.auth.callback.TextCallbackHandler;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import java.util.Hashtable;
import common.JndiAction;
import common.utils;
import Activator.Config;
import Activator.Match;
import application.DhcpHostsController;

@Controller
public class LoginController {

    @Autowired
    private DhcpHostsController hostsController;

    //
    // This code will use GSSAPI if the browser can send it
    // Otherwise normal login
    //
    // Assume mod_auth_gssapi is set up also. This code handles
    // GSSAPI auth for LDAP, but the Java GSSAPI APIs can't create
    // kerberos credential caches. Since we use IPA commands to make
    // some changes, we need a credential case for the user.
    // mod_auth_gssapi sets those up. So if the browser send GSSAPI
    // it is processed twice, by mod_auth_gssapi and this code.
    //
    // We can't rely on just mod_auth_gssapi,
    // because the Java GSSAPI code has no way to use a credential
    // cache that uses constrained delegation. So we need to use
    // both mod_auth_gssapi and Java GSSAPI
    //
    // The underlying problem is that Java has two separate
    // implementations of Kerberos, GSSAPI and an older Kerberos.
    // They use different classes, and you can't move things
    // between them exception in a few cases. 
    //
    // LDAP authentication can be done with either a GSSAPI
    // credential or a traditional Kerberos subject, but the
    // LDAP interface for them is different. For a traditional Kerberos
    // login, you get a Subject from login, and use it with doAs
    // For GSSAPI, you get a GSSCredential. It is set up as
    // an attribute in the usual LDAP attribute array.
    //
    // To simplify the code, we always use doAs, but with
    // GSSAPI login, the doAs subject is ignored, because
    // an explicit GSSCredential takes precedent.

    //
    // Support for login with password
    //

    // call skinit command in a fork to take the user's password and
    // generate a Kerberos credential file, /tmp/krb5cc_USER_PID.
    // This is the actual login. 

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

    // Login can get credentials in various ways: prompting for
    // a password, a key table, or existing credentials from a credential
    // cache. This configurtion object tells it to use a credential
    // cache, i.e. /tmp/krb5_USER_PID.

    class KerberosConfiguration extends Configuration { 
        private String cc;
	private String principal;
 
        public KerberosConfiguration(String cc, String principal) { 
            this.cc = cc;
	    this.principal = principal;;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useTicketCache", "true"); 
            options.put("refreshKrb5Config", "true"); 
	    options.put("ticketCache", cc);
	    options.put("principal", principal);
	    
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 

    //
    // Support for GSSAPI login
    //

    // subject for our service principal
    // Note that the GSSAPI protocol requires us to use a
    // principla that is HTTP/hostname. HTTP must be upper case
    // principals are case-sensitive, at least for Linux
    public Subject getServiceSubject () {
	Subject subject = new Subject();
	Krb5LoginModule krb5LoginModule = new Krb5LoginModule();
	Map<String,String> optionMap = new HashMap<String,String>();

	optionMap.put("keyTab", "/etc/krb5.keytab.http");
	try {
	    optionMap.put("principal", "HTTP/" + InetAddress.getLocalHost().getHostName() + "@" + Config.getConfig().kerberosdomain); 
	} catch (Exception e) {
	    System.out.println("exception in getservicesubject getlocalhost " + e.toString());
	    return null;
	}
	optionMap.put("doNotPrompt", "true");
	optionMap.put("refreshKrb5Config", "true");
	// if these are set, storekey fails
	//	optionMap.put("useTicketCache", "true");
	//	optionMap.put("renewTGT", "true");
	optionMap.put("useKeyTab", "true");
	optionMap.put("storeKey", "true");
	optionMap.put("isInitiator", "true"); // needed for delegation
	optionMap.put("debug", "true"); // trace will be printed on console

	try {
	    krb5LoginModule.initialize(subject, null, new HashMap<String,String>(), optionMap);

	    krb5LoginModule.login();
	    krb5LoginModule.commit();
	} catch (Exception e) {
	    System.out.println("exception in getservicesubject " + e.toString());
	    return null;
	}

	return subject;
    }

    // GSSCredential for the string passed from client in the Authenticate token
    // this code will only work if constained delgaton is set up
    // "token" is the argument the browser passed us in the Authenticate header
    public GSSCredential validateTicket(Subject serviceSubject, byte[] token) {
	try {
	    return Subject.doAs(serviceSubject, new KerberosValidateAction(token));
	} catch (Exception e) {
	    System.out.println("exception in validateticker " + e.toString());
	    return null;
	}
    }

    // helpeer for above. This handles constrained delegeation, so we actually
    // get a credential that will work on behalf of the user
    private class KerberosValidateAction implements PrivilegedExceptionAction<GSSCredential> {
	byte[] kerberosTicket;

	public KerberosValidateAction(byte[] kerberosTicket) {
	    this.kerberosTicket = kerberosTicket;
	}

        @Override
	public GSSCredential run() throws Exception {
	    byte[] responseToken = new byte[0];
	    GSSName gssName = null;
	    GSSContext context = GSSManager.getInstance().createContext((GSSCredential) null);

	    while (!context.isEstablished()) {
		responseToken = context.acceptSecContext(kerberosTicket, 0, kerberosTicket.length);
		gssName = context.getSrcName();
		if (gssName == null) {
		    throw new BadCredentialsException("GSSContext name of the context initiator is null");
		}
	    }

	    //check if the credentials can be delegated
	    if (!context.getCredDelegState()) {
		throw new BadCredentialsException("Credentials can not be delegated. Please make sure that delegation is enabled for the service user. This may cause failures while creating Kerberized application.");
	    }

	    // only accepts the delegated credentials from the calling peer
	    GSSCredential clientCred = context.getDelegCred(); // in case of Unconstrained Delegation, you get the end user's TGT, otherwise TGS only
	    return clientCred;
	}
    }

    // these are entry points for other modules that need a login
    // initially they called the real loginGet. However since loginGet has
    //   to return ModelAndView and the callers return String,
    //   I've turned them into redirects. That's what you'd normally do anyway

    public String loginGet(String app, HttpServletRequest request, HttpServletResponse response, Model model) {
	String url = "/accounts/groups/login";
	if (app != null)
	    url = url + "?app=" + app;
	try {
	    response.sendRedirect(url);
	} catch (Exception ignore) {}
	return "groups/login";
    }

    public String loginGet(String app, Integer ifid, HttpServletRequest request, HttpServletResponse response, Model model) {
	String url = "/accounts/groups/login";
	String sep = "?";
	if (app != null) {
	    url = url + sep + "app=" + app;
	    sep = "&";
	}
	if (ifid != null)
	    url = url + sep + "ifid=" + ifid;
	try {
	    response.sendRedirect(url);
	} catch (Exception ignore) {}
	return "groups/login";
    }

    @GetMapping("/groups/login")
    public ModelAndView loginGet(@RequestParam(value="app", required=false) String app,
			   // have to pass this through for dhcp
			   @RequestParam(value="ifid", required=false) Integer ifid,
			   @RequestParam(value="logout", required=false) Boolean logout,
			    HttpServletRequest request, HttpServletResponse response, Model model) {

	List<String>messages = new ArrayList<String>();
	model.addAttribute("messages", messages);
	model.addAttribute("logout", logout);
	boolean requestNegotiation = false;

	if (logout != null && logout) {
	    request.getSession().removeAttribute("privs");
	    request.getSession().removeAttribute("krb5subject");
	    request.getSession().removeAttribute("krb5user");
	    request.getSession().removeAttribute("gssapi");
	}

	// find negotiateheader if any
	String negotiateHeader = null;
	var headers = request.getHeaderNames();
	while (headers.hasMoreElements()) {
	    var name = headers.nextElement();
	    if (name.equalsIgnoreCase("authorization"))
		negotiateHeader = request.getHeader(name).toString();
	}

	// these are set by mod_auth_gssapi if it
	// recognized the header
	var remoteUser = request.getRemoteUser();
	var authType = request.getAuthType();
	String user = null;

	// See if we have valid GSSAPI authentication
	// Authtype means the mod_auth_gssapi auth works, in which case
	//    we have a credential cache to copy
	// Negotiateheader indicates that the daata got passed to us so
	//    we can use gssapi with LDAP.
	// The negotiate header is processed twice, by mod_auth_gssapi, then us
	if ((logout == null || !logout) &&
	    "Negotiate".equals(authType) && remoteUser != null && remoteUser.indexOf("@") > 0 &&
	    negotiateHeader != null && negotiateHeader.startsWith("Negotiate ")) {

	  // stupid loop to simulate godo. this loop runs once
	  for (var f = 0; f < 1; f++) {
	    LoginContext lc = null;

	    // mod_auth_gssapi put the credential cache in /var/run/httpd/clientcaches
	    // put it in /tmp/krb5cc_USER where the rest of our code expects it

	    try {
		List<String>nmessages = new ArrayList<String>();
		var source = Paths.get("/var/run/httpd/clientcaches/" + remoteUser);
		user = remoteUser.substring(0,  remoteUser.indexOf("@CS.RUTGERS.EDU"));
		var dest = Paths.get("/tmp/krb5cc_" + user);
		Files.copy(source, dest, StandardCopyOption.REPLACE_EXISTING);
	    } catch (Exception e) {
		messages.add("Exception trying to create subject " + e.toString());
		break;
	    }


	    // now process the GSSAPI header
	    // data is a base64-encoded ticket
	    Base64.Decoder decoder = Base64.getMimeDecoder();
	    byte[] token = decoder.decode(negotiateHeader.substring(10));

	    // subj will be a Subject based on our service keytab
	    
	    Subject subj = getServiceSubject();
	    if (subj == null) {
		messages.add("Automatic login failed: unable to get ticker for our own service");
		break;
	    }

	    // produce GSScredential fron the ticket we got passed in the header
	    GSSCredential cred = validateTicket(subj, token);
	    if (cred == null) {
		messages.add("Automatic login failed: unable to convert authorization header from brower into Kerberos credentials");
		break;
	    }
	    // remember the GSSCredential for the rest of the session
	    // this attribute is needed whenever we use LDAP
	    request.getSession().setAttribute("gssapi", cred);

	    // at this point we have valid GSSAPI authentication.
	    // do the other stuff from loginSubmit: figure out
	    // user's privileges, and then save everything
	    // in the session

	    String filter = "(uid=" + user + ")";

	    // get data on the user who is logging in
	    common.JndiAction action = new common.JndiAction(cred, new String[]{filter, ""});
	    
	    Subject.doAs(subj, action);

	    // has to have data in our LDAP or login can't have worked
	    if (action.val.size() == 0) {
		messages.add("Unable to get information on ourself from LDAP");
		break;
	    }
	    var ourData = action.data.get(0);

	    // now check privs
	    Config conf = Config.getConfig();
	    Set<String>privs = new HashSet<String>();

	    // Can add group?
	    if (Match.matchLdap(ourData, conf.groupmanagerfilter))
		privs.add("addgroup");

	    // DHCP manager?
	    if (Match.matchLdap(ourData, conf.dhcpmanagerfilter))
		privs.add("dhcpmanager");

	    // now see if they are in login mangers. They can set login attribute
	    if (Match.matchLdap(ourData, conf.loginmanagerfilter)) 
		privs.add("loginmanager");

	    // see if they are superusr
	    if (Match.matchLdap(ourData, conf.superuserfilter)) 
		privs.add("superuser");

	    // now set up session and go to application
	    // Note that the "gssapi" attribute will actually be
	    // used by LDAP for authentication. To avoid complicating
	    // the code we still set krb5subject. It will be used in
	    // doAs, but it wil actually be ignored, since gssapi will
	    // override it. The doAs is needed when we login with a password
	    request.getSession().setAttribute("privs", privs);
	    request.getSession().setAttribute("krb5subject", subj);
	    request.getSession().setAttribute("krb5user", user);

	    // gssapi failed, will do normal login

	  } // end of dummy loop

	} else {
	    // Didn't have a GSSAPI header. Ask for one.
	    //
	    // When this happens we display the login
	    // page as an error page (401 error), with
	    // the header "WWW-Authenticate: negotiate"
	    //
	    // If the browser can to GSSAPI it tries again
	    // with the Authentication header. Otherwise
	    // it display the login page and we do a
	    // manual login
	    requestNegotiation = true;
	}
	// end of GSSAPI. This code is done in either case

	model.addAttribute("app", (app == null) ? "" : app);
	try {
	    // if attribute is set, we are logged in, either
	    // we already were or GSSAPI has just done it
	    // dispatch to the right application
	    if (request.getSession().getAttribute("krb5subject") != null) {
		if ("user".equals(model.asMap().get("app")))
		    response.sendRedirect("../users/showuser");
		if ("hosts".equals(model.asMap().get("app")))
		    response.sendRedirect("../hosts/showhosts");
		if ("dhcp".equals(model.asMap().get("app"))) {
		    // if ifid is set, this is a login from the inventory app
		    // want to search for the interface with this id
		    if (ifid != null)
			response.sendRedirect("../dhcp/showhosts?ifid=" + ifid);
		    else 
			response.sendRedirect("../dhcp/showsubnets");
		} else {
		    response.sendRedirect("showgroups");
		}
	    }
	} catch (Exception e){
	}
	// not logged in. Show login screen

	// need to pass this through for the inventory entrypoint
	model.addAttribute("ifid", ifid);

	// if we didn't get GSSAPI info from the browser, ask for it
	// in either case display login screen.  If www-authenticate
	// is sent and the brwoser can do GSSAPI it will resubmit
	// the original request with GSSAPI information. Otherwise
	// it shows the login screen
	//
	// If GSSAPI authentication worked, we redirected into
	// the application
	//
	// Using ModelAndView is the only way to generate a 401.
	// You can't just set status in response. Spring will override it
	if (requestNegotiation) {
	    response.setHeader("WWW-Authenticate", "Negotiate");
	    return new ModelAndView("groups/login", model.asMap(), HttpStatus.UNAUTHORIZED);
	} else
	    return new ModelAndView("groups/login", model.asMap());

    }

    @PostMapping("/groups/login")
    public String loginSubmit(@RequestParam(value="app", required=false) String app,
			      @RequestParam(value="ifid", required=false) Integer ifid,
			      @RequestParam(value="user", required=false) String user,
			      @RequestParam(value="pass", required=false) String pass,
			      @RequestParam(value="logout", required=false) Boolean logout,
			      HttpServletRequest request, HttpServletResponse response,
			      Model model) {

	List<String>messages = new ArrayList<String>();
	model.addAttribute("messages", messages);
	model.addAttribute("logout", logout);

	LoginContext lc = null;
	String username = filteruser(user);
	String password = filterpass(pass);

	if (!username.equals(user)) {
	    return "groups/login";
	}

	// make credentials cache. This calls skinit in a process,
	// passing it the password the user supplied. Output is
	// a Kerberos credential file, /tmp/krb5cc_USER_PID.
	// This is the real login.


	String cc = makeCC (username, password, messages);
	if (cc == null) {
	    // should have gotten error message already
	    return "groups/login";
	}

	// Do the Java login. Output is a Subject. With the arguments we're using
	// the login should succeed. We already did skinit and got a valid
	// Kerberos ticket, so the hard part is done. This just generates the
	// Java data structure, Subject, with the credentials from the ticket.
	// With other options, login might have to do the Kerberos login itself,
	// either from a password or a key table. We don't do that because (1)
	// Java login can't handle one-time passwords, and (2) we need a credential
	// cache for each user that's logged in to use with IPA commands. That
	// credential has to be something the IPA command can handle. The simplest
	// is a traditional key table file in /tmp. A funny Java object won't mean
	// anything to a command-line program like IPA.

	Configuration kconfig = new KerberosConfiguration(cc, username );
	try {
	    lc = new LoginContext("Groups", null, null, kconfig);
	    lc.login();
	} catch (LoginException le) {
	    messages.add("Cannot create LoginContext. " + le.getMessage());
	    return "groups/login";
	} catch (SecurityException se) {
	    messages.add("Cannot create LoginContext. " + se.getMessage());
	    return "groups/login";
	}

	Subject subj = lc.getSubject();  
	if (subj == null) {
	    messages.add("Login failed");
	    return "groups/login";
	}

	// check group privs
   

	String filter = "(uid=" + username + ")";

	// get data on the user who is logging in
	common.JndiAction action = new common.JndiAction(null, new String[]{filter, ""});

	Subject.doAs(subj, action);
	// has to have data in our LDAP or login can't have worked
	if (action.val.size() == 0) {
	    messages.add("Login failed");
	    return "groups/login";
	}

	var ourData = action.data.get(0);

	// now check privs
	Config conf = Config.getConfig();
	Set<String>privs = new HashSet<String>();

	// Can add group?
	if (Match.matchLdap(ourData, conf.groupmanagerfilter))
	    privs.add("addgroup");

	// DHCP manager?
	if (Match.matchLdap(ourData, conf.dhcpmanagerfilter))
	    privs.add("dhcpmanager");

	// now see if they are in login mangers. They can set login attribute
	if (Match.matchLdap(ourData, conf.loginmanagerfilter)) 
	    privs.add("loginmanager");

	// see if they are superusr
	if (Match.matchLdap(ourData, conf.superuserfilter)) 
	    privs.add("superuser");

	// now set up session and go to application
	request.getSession().setAttribute("privs", privs);
	request.getSession().setAttribute("krb5subject", subj);
	request.getSession().setAttribute("krb5user", username);
	try {
	    if ("user".equals(app)) {
		response.sendRedirect("../users/showuser");
	    } else if ("hosts".equals(app)) {
		response.sendRedirect("../hosts/showhosts");
	    } else if ("dhcp".equals(app)) {
		// if ifid is set, this is a login from the inventory app
		// want to search for the interface with this id
		if (ifid != null)
		    return hostsController.hostsGet(ifid, request, response, model);
		else
		    response.sendRedirect("../dhcp/showsubnets");
	    } else
		response.sendRedirect("showgroups");
	} catch (Exception e) {
	    messages.add("Unable to redirect to main application: " + e);
	    return "groups/login";
	}

	// shouldn't happen
        return "groups/login";
    }

}
