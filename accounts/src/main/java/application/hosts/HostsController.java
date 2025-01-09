/*
 * Copyright 2018 by Rutgers, the State University of New Jersey
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

// lets a user display hosts that they manage and add new hosts

package application;

import java.util.List;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.text.SimpleDateFormat;
import java.net.InetAddress;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import java.security.Principal;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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

@RestController
public class HostsController {

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

    // this class is used to set up a configuration that uses the principal http/services.cs.rutgers.edu
    // It is passed to LoginContext to generate a subject. Most documentation says that the
    // info here has to go into a file, but it's a lot easier to do it in code.

    class ServicesConfiguration extends Configuration { 
        private String cc;
 
        public ServicesConfiguration(String cc) { 
            this.cc = cc;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useKeyTab", "true"); 
	    options.put("principal", Config.getConfig().servicesprincipal); 
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

    // output is either a key table or an error message. There is no ambiguity
    // because key tables start with a binary 5. To be sure I'm starting all messages with Error:

    // this is authetnciated by LDAP basic auth. It's set up in SpringSecurityConfig.java
    // Note that it is set for this specific URL only. Everything else is done using our own
    // login authentication.
    // show info for current user
    @GetMapping("/enrollhosts")
    @ResponseBody
    public byte[] hostsGet(@RequestParam(value="host", required=false) String hostname,
			   HttpServletRequest request, HttpServletResponse response, Principal principal) {

	List<String> messages;
	final String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/user/bin"};
	final Logger logger = LogManager.getLogger();

	if (hostname == null)
	    return "Error: you must supply a host parameter".getBytes();

	int port = request.getRemotePort();
	if (port >= 1024)
	    return "Error: you must be root to use this".getBytes();

	// check both that the hostname supplied (which should be the system's hostname) matches the
	// ip address and the fully-qualified hostname. If things don't all agree Kerberos may not
	// work properly.

	String remoteAddrString = request.getRemoteAddr();

	// need to match InetAddress. String isn't good enough, because IPv6 addresses
	// can be represented different ways. getByName works with an IP address as well as hostname,
	// so this converts the string representation of the remote IP address to an InetAddress object
	InetAddress remoteAddr;
	try {
	    remoteAddr =  InetAddress.getByName(remoteAddrString);
	} catch (java.net.UnknownHostException uhe) {
	    return ("Error: can't parse address " + remoteAddrString).getBytes();
	}
	
	InetAddress[] remoteAddrs;
	try {
	    remoteAddrs = InetAddress.getAllByName(hostname);
	} catch (java.net.UnknownHostException uhe) {
	    return ("Error: can't find host " + hostname + " in DNS").getBytes();
	}
	boolean foundAddr = false;
	
	for (int i = 0; i < remoteAddrs.length; i++) {
	    if (remoteAddrs[i].equals(remoteAddr)) {
		if (!hostname.equals(remoteAddrs[i].getCanonicalHostName())) {
		    return ("Error: the hostname you supplied, " + hostname + ", doesn't agree with the full hostname for your IP address, " + remoteAddrs[i].getCanonicalHostName()).getBytes();
		}
		foundAddr = true;
	    }
	}
	if (!foundAddr)
	    return ("Error: the hostnae specified " + hostname + " doesn't agree with the address you're coming from, " + remoteAddr).getBytes();

	// set up for LDAP operations
	Configuration sconfig = makeServicesConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, sconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext for services. " + le.getMessage());
	    return "Error: HostsController Can't setup authentication".getBytes();
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext for services. " + se.getMessage());
	    return "Error: HostsController Can't setup authentication".getBytes();
	}

	Subject servicesSubject = lc.getSubject();  
	if (servicesSubject == null) {
	    logger.error("LoginContext has empty subject");
	    return "Error: HostsController Can't setup authentication".getBytes();
	}

	// we need either an authorized user or a host in hostgroup self-managed

	// if no user, better be in the hostgroup
	if (principal == null || principal.getName() == null) {

	    // look up hostgroup in LDAP
	    var filter = Config.getConfig().selfmanagedfilter.replace("$HOST", hostname);
	    common.JndiAction action = new common.JndiAction(null, new String[]{filter, "", "dn"});

	    Subject.doAs(servicesSubject, action);

	    if (action.val == null || action.val.size() == 0) {
		return "Error: your host is not registered as self-managed".getBytes();
	    }

	    // end if not principal specified. At this point the host has been checked,
	    // so it's OK to get a key table
	} else {

	// we have a principal. If it's authorized, we can add the host

        // yes. verify that they're in the right group, and try to add the host

	String user = principal.getName();
	var filter = "(&(uid=" + user + ")" + Config.getConfig().addhostsfilter + ")";

	common.JndiAction action = new common.JndiAction(null, new String[]{filter, "", "dn"});

	Subject.doAs(servicesSubject, action);

	if (action.val == null || action.val.size() == 0) {
	    return ("Error: HostController: " + user + " is not authorized to add hosts").getBytes();
	}

	// the hosts add code is in the alternative with a principal
	// without a principal we can get a new key table, but not add the host

	messages = new ArrayList<String>();
	logger.info("ipa host-add " + hostname + " --addattr=nshostlocation=research-user");

	if (docommand.docommand (new String[]{"/bin/ipa", "host-add", hostname, "--addattr=nshostlocation=research-user"}, env, messages) != 0) {
	    boolean exists = false;
	    String errmsg = "Error: ";
	    for (String m:messages) {
		// can't add to messages while we're looping over it, so set flag
		errmsg += " " + m;
		if (m.contains("already exists"))
		    exists = true;
	    }
	    if (!exists)
		return errmsg.getBytes();

	}

	// tell all the kerberos servers to update their firewalls

	String sshenv[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/user/bin"};

	// look up kerberos servers in DNS
	String query = "_kerberos._tcp." + Config.getConfig().kerberosdomain;
	Hashtable<String, String> environment = new Hashtable<String, String>();
	environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
	environment.put("java.naming.provider.url", "dns:");
	// do DNS lookup of _kerberos._tcp.cs.rutgers.edu
	try {
	    InitialDirContext dirContext = new InitialDirContext(environment);
	    javax.naming.NamingEnumeration records = dirContext.getAttributes(query, new String[] {"SRV"}).getAll();
	    // iterate over results
	    while (records.hasMore()) {
		javax.naming.directory.Attribute attr = (javax.naming.directory.Attribute) records.next();
		javax.naming.NamingEnumeration addrs = attr.getAll();
		while (addrs.hasMore()) {
		    String addr = (String)addrs.next();
		    // record looks like 0 100 88 krb2.cs.rutgers.edu.
		    // so we need the 4th element
		    String[] hostinfo = addr.split(" ", 4);
		    String host = hostinfo[3];

		    // got it. Now prod the server. See README for how this is set up.
		    // it's a Rube Goldberg contraption that ends up running the firewall update
		    // on all the servers. Just need to ssh to the host. There's a forced command.
		    logger.info("ssh syncipt@" + host);
		    // don't check the results. batch job will fix it up
		    if (docommand.docommand (new String[]{"/bin/ssh", "syncipt@" + host}, sshenv) != 0) {
			logger.info("ssh to kerberos server failed");
		    }
		}
	    }
	} catch (Exception e) {
	    logger.info("attempt to get kerberos server hosts failed " + e);
	}

	// in case old file is still around, delete it
	try {
	    File file = new File("/tmp/" + hostname + ".kt");
	    file.delete();
	} catch (Exception igore) {
	}

	}

	// end of code to add the host, which is the alternative for authorized user

	// get a new key table, if either authorized user or self-managed host

	logger.info("ipa-getkeytab -p host/" + hostname + " -k /tmp/" + hostname + ".kt");
	messages = new ArrayList<String>();
	if (docommand.docommand (new String[]{"/sbin/ipa-getkeytab", "-p", "host/" + hostname, "-k", "/tmp/" + hostname + ".kt"}, env, messages) != 0) {
	    String errmsg = "Error: ";
	    for (String m:messages) {
		errmsg += " " + m;
	    }
	    return errmsg.getBytes();
	}

	// normal hosts don't need nfs/hostname. host/hostname will be
	// used instead. For nfs servers this will increment the version
	// number for an existing server. So it's best to leave this 
	// principal to be done manually

	//	logger.info("ipa service-add nfs/" + hostname);
	//	messages = new ArrayList<String>();
	//	if (docommand.docommand (new String[]{"/bin/ipa", "service-add", "nfs/" + hostname}, env, messages) != 0) {
	//	    boolean exists = false;
	//	    String errmsg = "Error: ";
	//	    for (String m:messages) {
	//		errmsg += " " + m;
	//		if (m.contains("already exists"))
	//		    exists = true;
	//	    }
	//	    if (!exists)
	//		return errmsg.getBytes();
	//	}

	//	logger.info("ipa-getkeytab -p nfs/" + hostname + " -k /tmp/" + hostname + ".kt");
	//	messages = new ArrayList<String>();
	//	if (docommand.docommand (new String[]{"/sbin/ipa-getkeytab", "-p", "nfs/" + hostname, "-k", "/tmp/" + hostname + ".kt"}, env, messages) != 0) {
	//	    String errmsg = "Error: ";
	//	    for (String m:messages) {
	//		errmsg += " " + m;
	//	    }
	//	    return errmsg.getBytes();
	//	    }

	try {
	    File file = new File("/tmp/" + hostname + ".kt");
	    FileInputStream fis = new FileInputStream(file);
	    byte[] data = new byte[(int) file.length()];
	    fis.read(data);
	    fis.close();
	    file.delete();

	    return data;
	} catch (Exception e) {
	    return "Error: can't read keytable from file".getBytes();
	}
    }

    // doesn't quite delete a host. rather, removes it from the group user-managed
    // do this once the OS installation is finished. That prevents someone from faking
    // your IP and stealing your key table.
    // this is authetnciated by LDAP basic auth. It's set up in SpringSecurityConfig.java
    // Note that it is set for this specific URL only. Everything else is done using our own
    // login authentication.
    @DeleteMapping("/enrollhosts")
    @ResponseBody
    public byte[] hostsDelete(@RequestParam(value="host", required=false) String hostname,
			   HttpServletRequest request, HttpServletResponse response, Principal principal) {

	List<String> messages;
	final String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/user/bin"};
	final Logger logger = LogManager.getLogger();

	System.out.println("start delete");

	if (hostname == null)
	    return "Error: you must supply a host parameter".getBytes();

	int port = request.getRemotePort();
	if (port >= 1024)
	    return "Error: you must be root to use this".getBytes();

	// check both that the hostname supplied (which should be the system's hostname) matches the
	// ip address and the fully-qualified hostname. If things don't all agree Kerberos may not
	// work properly.

	String remoteAddr = request.getRemoteAddr();
	InetAddress[] remoteAddrs;
	try {
	    remoteAddrs = InetAddress.getAllByName(hostname);
	} catch (java.net.UnknownHostException uhe) {
	    return ("Error: can't find host " + hostname + " in DNS").getBytes();
	}
	boolean foundAddr = false;
	for (int i = 0; i < remoteAddrs.length; i++) {
	    if (remoteAddrs[i].getHostAddress().equals(remoteAddr)) {
		if (!hostname.equals(remoteAddrs[i].getCanonicalHostName())) {
		    return ("Error: the hostname you supplied, " + hostname + ", doesn't agree with the full hostname for your IP address, " + remoteAddrs[i].getCanonicalHostName()).getBytes();
		}
		foundAddr = true;
	    }
	}
	if (!foundAddr)
	    return ("Error: the hostnae specified " + hostname + " doesn't agree with the address you're coming from, " + remoteAddr).getBytes();

	// set up for LDAP operations
	Configuration sconfig = makeServicesConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, sconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext for services. " + le.getMessage());
	    return "Error: HostsController Can't setup authentication".getBytes();
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext for services. " + se.getMessage());
	    return "Error: HostsController Can't setup authentication".getBytes();
	}

	Subject servicesSubject = lc.getSubject();  
	if (servicesSubject == null) {
	    logger.error("LoginContext has empty subject");
	    return "Error: HostsController Can't setup authentication".getBytes();
	}

	// don't check permission. We'll just try to remove it. If it isn't
	// in the group that will fail.

	// the hosts add code is in the alternative with a principal
	// without a principal we can get a new key table, but not add the host

	messages = new ArrayList<String>();
	logger.info("ipa hostgroup-remove-member " + Config.getConfig().selfmanagedgroup + " --hosts=" + hostname);

	if (docommand.docommand (new String[]{"/bin/ipa", "hostgroup-remove-member", Config.getConfig().selfmanagedgroup, "--hosts=" + hostname}, env, messages) != 0) {
	    boolean notmember = false;
	    String errmsg = "Error: ";
	    for (String m:messages) {
		// can't add to messages while we're looping over it, so set flag
		errmsg += " " + m;
		if (m.contains("is not a member"))
		    notmember = true;
	    }
	    if (notmember)
		return "ok".getBytes();
	    else
		return errmsg.getBytes();

	}
	
	return "ok".getBytes();

    }


}
