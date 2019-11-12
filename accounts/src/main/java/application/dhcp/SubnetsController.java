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
import java.util.Calendar;
import java.util.HashSet;
import java.text.SimpleDateFormat;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.Charset;
import java.io.PrintWriter;
import java.io.IOException;
import javax.naming.NamingException;
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
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.security.auth.kerberos.KerberosTicket;
import javax.naming.directory.Attributes;
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
import org.apache.commons.net.util.SubnetUtils;

@Controller
public class SubnetsController {

    @Autowired
    private LoginController loginController;

    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^.0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    public boolean checkSubnetEntry(List<String>messages, BasicAttribute cn, String netmask, BasicAttribute dhcpOption) {
	Logger logger = null;
	logger = LogManager.getLogger();
	var charset = Charset.forName("US-ASCII");
	Path temppath = null;
	try {
	    temppath = Files.createTempFile("dhcpcheck", null);
	} catch (IOException x) {
	    messages.add("Can't create temp file " + x);
	    logger.error("Can't create temp file " + x);
	    return false;
	}

	try (PrintWriter writer = new PrintWriter(Files.newBufferedWriter(temppath, charset))) {
	    writer.println("subnet " + (String)cn.get() + " netmask " + netmask + "{");
	    var e = dhcpOption.getAll();
	    try {
		while (e.hasMore()) {
		    var value = (String) e.next();
		    if (value.endsWith(";"))
			writer.println("option " + value);
		    else
			writer.println("option " + value + ";");
		}
	    } catch (Exception x) {
		try {Files.deleteIfExists(temppath);}catch(Exception ignore){}
		messages.add("Error writing temp file: " + x);
		logger.error("Error writing temp file: " + x);
		return false;
	    } finally {
		e.close();
	    }
	    writer.println("}");
	} catch (IOException x) {
	    try {Files.deleteIfExists(temppath);}catch(Exception ignore){}
	    messages.add("Error writing temp file: " + x);
	    logger.error("Error writing temp file: " + x);
	    return false;
	} catch (NamingException x) {
	    try {Files.deleteIfExists(temppath);}catch(Exception ignore){}
	    messages.add("Error writing temp file: " + x);
	    logger.error("Error writing temp file: " + x);
	    return false;
	} 
	var errout = new ArrayList<String>();
	if (docommand.docommand (new String[]{"/usr/sbin/dhcpd", "-t", "-cf", temppath.toString()},
				 new String[]{"PATH=/sbin:/bin:/usr/sbin:/usr/bin","HOME=/tmp"}, errout) != 0) {
	    try {Files.deleteIfExists(temppath);}catch(Exception ignore){}
	    messages.add("There is a problem with one of the options you specified");
	    messages.addAll(errout);
	    return false;
	}
	try {Files.deleteIfExists(temppath);}catch(Exception ignore){}
	return true;
    }    
    
    @GetMapping("/dhcp/showsubnets")
    public String subnetsGet(HttpServletRequest request, HttpServletResponse response, Model model) {
	// This module uses Kerberized LDAP. The credentials are part of a Subject, which is stored in the session.
	// This JndiAction junk is needed to execute the LDAP code in a context that's authenticated by
	// that Subject.

	Config conf = Config.getConfig();
	var privs = (Set<String>)request.getSession().getAttribute("privs");
	
	Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	if (subject == null) {
	    List<String> messages = new ArrayList<String>();
	    messages.add("Session has expired");
	    model.addAttribute("messages", messages);
	    return loginController.loginGet("dhcp", request, response, model); 
	}

	// I use an API I wrote around Sun's API support.
	// See comments on showgroup.jsp

	// this action isn't actually done until it's called by doAs. That executes it for the Kerberos subject using GSSAPI
	common.JndiAction action = new common.JndiAction(new String[]{"objectclass=dhcpsubnet", conf.dhcpbase, "cn", "dhcpnetmask", "dhcpoption"});

	// save context for lookup
	action.noclose = true;
	Subject.doAs(subject, action);
	var ctx = action.ctx;

	// look at the results of the LDAP query
	var subnets = action.data;
	Collections.sort(subnets, (g1, g2) -> DhcpHostsController.getIntAddress(g1,"cn").compareTo(DhcpHostsController.getIntAddress(g2, "cn")));

	// set up model for JSTL to output
	model.addAttribute("subnets", subnets);
	model.addAttribute("dhcpmanager", (privs.contains("dhcpmanager")));
	model.addAttribute("superuser", (privs.contains("superuser")));

	try {
	    var dn = "cn=config," + conf.dhcpbase;
	    var attrs = ctx.getAttributes(dn, new String[]{"dhcpoption"});
	    var options = attrs.get("dhcpoption").getAll();
	    model.addAttribute("options", options);
	} catch (Exception ignore) {}	    

        return "/dhcp/showsubnets";
    }

    // increment the serial number for the configuration
    // this tells the DHCP servers to reread configuration
    public void incrementSerial(DirContext ctx) {

	var dn = "cn=config," + Config.getConfig().dhcpbase;

	// I don't check for nulls because they are unlikely, and
	// would generate exceptions that try will get
	try {
	    var attrs = ctx.getAttributes(dn, new String[]{"dhcpcomments"});

	    var comment = (String)attrs.get("dhcpcomments").get();
	    var serial = Long.parseLong(comment);
	    
	    serial ++;

	    var newcomments = new BasicAttribute("dhcpcomments", Long.toString(serial));
	    var newAttributes = new BasicAttributes();
	    newAttributes.put(newcomments);
	    ctx.modifyAttributes(dn, DirContext.REPLACE_ATTRIBUTE, newAttributes);

	} catch (Exception ignore) {
	    System.out.println("incrementserial " + ignore.toString());
	}

    }	

    @PostMapping("/dhcp/showsubnets")
    public String subnetsSubmit(@RequestParam(value="name", required=false) String name,
			       @RequestParam(value="origname", required=false) String origname,
			       @RequestParam(value="routers", required=false) String routers,
			       @RequestParam(value="options", required=false) String options,
			       @RequestParam(value="del", required=false) List<String>del,
			       HttpServletRequest request, HttpServletResponse response,
			       Model model) {

	List<String>messages = new ArrayList<String>();
	model.addAttribute("messages", messages);
	((List<String>)model.asMap().get("messages")).clear();

	Logger logger = null;
	logger = LogManager.getLogger();

	Config conf = Config.getConfig();
	var privs = (Set<String>)request.getSession().getAttribute("privs");


	// user has asked to modify subnets but doesn't have permission
	if (!(privs.contains("dhcpmanager")) && !(privs.contains("superuser"))) {
	    messages.add("You don't have permission to manage DHCP");
	    model.addAttribute("messages", messages);
	    return subnetsGet(request, response, model);
	}

	if (del != null && del.size() > 0) {
	    Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	    if (subject == null) {
		messages.add("Session has expired");
		model.addAttribute("messages", messages);
		return loginController.loginGet("dhcp", request, response, model); 
	    }

	    // no filter, so no search. this is just to get a context
	    common.JndiAction action = new common.JndiAction(new String[]{null, conf.dhcpbase});
	    action.noclose = true;

	    Subject.doAs(subject, action);

	    var ctx = action.ctx;

	    for (String d: del) {
		var dn = "cn=" + d + ",cn=config," + conf.dhcpbase;
		try {
		    ctx.destroySubcontext(dn);
		} catch (javax.naming.NamingException e) {
		    messages.add("Unable to delete " + d + ": " + e.toString());
		    model.addAttribute("messages", messages);
		}
	    }

	    // if there's an add request also, update the serial after that's done
	    if (name != null && ! "".equals(name.trim()))
		incrementSerial(ctx);

	    try {
		ctx.close();
	    } catch (Exception ignore) {
	    }
	}

	// if no name specified, nothing more to do
	if (name == null || "".equals(name.trim()))
	    return subnetsGet(request, response, model);

	// if we're here there is a new subnet or a subnet to be updated.
	// so we can tell the difference, the original entry name (cn)
	// is passed in origname when an existing entry is updated.
	// otherwise it's a new entry. Note that it makes no sense to
	// rename a subnet, so we actually ignore the value of origname

	var isUpdate = origname != null && !origname.isBlank();

	name = name.trim();

	// this will do a real parse. As long as it's OK, we
	// can then use things to indexOf. 
	SubnetUtils subnetu = null;
	try {
	    subnetu = new SubnetUtils(name);
	} catch (IllegalArgumentException ignore) {
	    messages.add("Subnet must be in format n.n.n.n/d");
	    model.addAttribute("messages", messages);
	    return subnetsGet(request, response, model);
	}

	var subnetInfo = subnetu.getInfo();
	var netmask = subnetInfo.getNetmask();
	var i = name.indexOf("/");
	var net = name.substring(0, i);
	var bits = name.substring(i+1);
	var broadcast = subnetInfo.getBroadcastAddress();
	var router = subnetInfo.getLowAddress();
	if (routers != null && !routers.isBlank())
	    router = routers;

	Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	if (subject == null) {
	    messages.add("Session has expired");
	    model.addAttribute("messages", messages);
	    return loginController.loginGet("dhcp", request, response, model); 
	}

	// no filter, so no search. this is just to get a context
	common.JndiAction action = new common.JndiAction(new String[]{null, conf.dhcpbase});
	action.noclose = true;

	Subject.doAs(subject, action);

	var ctx = action.ctx;

	var oc = new BasicAttribute("objectClass");
	oc.add("top");
	oc.add("dhcpSubnet");
	oc.add("dhcpOptions");

	var cn = new BasicAttribute("cn", net);
	var dhcpNetMask = new BasicAttribute("dhcpNetMask", bits);
	var dhcpOption = new BasicAttribute("dhcpOption");

	// user has supplied this option
	var haveOptions = new HashSet<String>();

	// add options specified by user, but also
	// remember which we've seen, so we don't add defaults
	// for them
	if (options != null && ! options.isBlank()) {
	    var lines = options.split("\n");
	    for (var line: lines) {
		line = line.trim();

		// remember we've seen this option
		var sp = line.indexOf(" ");
		if (sp > 0)
		    haveOptions.add(line.substring(0, sp));

		dhcpOption.add(line);
	    }
	}

	if (!isUpdate) {
	    if (! haveOptions.contains("broadcast-address"))
		dhcpOption.add("broadcast-address " + broadcast);
	    if (! haveOptions.contains("routers"))
		dhcpOption.add("routers " + router);
	    if (! haveOptions.contains("subnet-mask"))
		dhcpOption.add("subnet-mask " + netmask);
	}

	var entry = new BasicAttributes();
	if (!isUpdate) {
	    // we don't ever change object class or cn
	    entry.put(oc);
	    entry.put(cn);
	}
	entry.put(dhcpNetMask);
	entry.put(dhcpOption);

	if (!checkSubnetEntry(messages, cn, netmask, dhcpOption)) {
	    messages.add("There is a problem with the options you specified, the DHCP server rejects them.");
	    model.addAttribute("messages", messages);
	    return subnetsGet(request, response, model); 
	}

	var dn = "cn=" + net + ",cn=config," + conf.dhcpbase;
	try {
	    if (isUpdate) {
		ctx.modifyAttributes(dn, DirContext.REPLACE_ATTRIBUTE, entry);
	    } else {
		var newctx = ctx.createSubcontext(dn, entry);
		newctx.close();
	    }
	} catch (Exception e) {
	    try {
		ctx.close();
	    } catch (Exception ignore) {}
	    messages.add((isUpdate ? "Can't modify entry: " : "Can't create new entry: ") + e.toString());
	    model.addAttribute("messages", messages);
	    return subnetsGet(request, response, model); 
	}

	incrementSerial(ctx);

	try {
	    ctx.close();
	} catch (Exception ignore) {}	    
	return subnetsGet(request, response, model);

    }

}
