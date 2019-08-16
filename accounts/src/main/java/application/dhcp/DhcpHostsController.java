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
import java.text.SimpleDateFormat;
import java.net.UnknownHostException;
import java.net.InetAddress;
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
import application.SubnetsController;
import Activator.Config;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.commons.net.util.SubnetUtils;

@Controller
public class DhcpHostsController {

    @Autowired
    private LoginController loginController;

    @Autowired
    private SubnetsController subnetsController;

    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^./0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    @GetMapping("/dhcp/showhosts")
    public String hostsGet(@RequestParam(value="subnet", required=false) String subnet,
			   HttpServletRequest request, HttpServletResponse response, Model model) {
	// This module uses Kerberized LDAP. The credentials are part of a Subject, which is stored in the session.
	// This JndiAction junk is needed to execute the LDAP code in a context that's authenticated by
	// that Subject.

	System.out.println("point 0 " + subnet);

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

	// default base, no subnet
	var base = conf.dhcpbase;
	if (subnet != null && !subnet.isBlank()) {
	    // subnet specified, find the object
	    var filtered = filtername(subnet);
	    // filter doesn't allow this
	    if (subnet.equals("orphanhosts"))
		filtered = "orphanhosts";
	    
	    var filter = "(&(objectclass=dhcpgroup)(cn=" + filtered + "))";
	    
	    System.out.println("filter " + filter + " base " + conf.dhcpbase);
	    common.JndiAction action = new common.JndiAction(new String[]{filter, conf.dhcpbase, "dn"});
	    Subject.doAs(subject, action);

	    // should be a list of 1 subnet entry
	    var entries = action.data;
	    System.out.println("subnet entries " + entries);
	    if (entries != null && entries.size() > 0) {
		// should have a list of one DN
		var dn = entries.get(0).get("dn");
		if (dn != null && dn.size() >= 0)
		    // search base for hosts is the DN of the subnet
		    base = dn.get(0);
	    }

	}
				
	// now look for all hosts within that search base
	
	System.out.println("point 1 " + base);

	common.JndiAction action = new common.JndiAction(new String[]{"(objectclass=dhcphost)", base, "cn", "dhcphwaddress", "dhcpstatements"});
	Subject.doAs(subject, action);

	var hosts = action.data;

	System.out.println("point 2 " + hosts);
	
	if (hosts != null && hosts.size() > 0) {
	    for (var host: hosts) {
		var statements = host.get("dhcpstatements");
		var address = "255.255.255.255"; // in case none found
		if (statements != null)
		    for (var statement: statements) {
			if (statement.startsWith("fixed-address")) {
			    var addresslist = statement.substring("fixed-address".length() + 1);
			    var addresses = addresslist.split("\\s+");
			    if (addresses.length > 0)
				address = addresses[0];
			}
		    }

		var addrs = new ArrayList<String>();
		addrs.add(address);
		host.put("address", addrs); // save for sort

	    }
	    // now entries is all the hosts that match the subnet specification
	    Collections.sort(hosts, (g1, g2) -> g1.get("address").get(0).compareTo(g2.get("address").get(0)));
	}

	System.out.println("point 3");

	model.addAttribute("subnet", subnet);
	model.addAttribute("hosts", hosts);
	model.addAttribute("dhcpmanager", (privs.contains("dhcpmanager")));
	model.addAttribute("superuser", (privs.contains("superuser")));

	System.out.println("displaying");

	return "/dhcp/showhosts";	
		
    }

    @PostMapping("/dhcp/showhosts")
    public String subnetsSubmit(@RequestParam(value="name", required=false) String name,
			       @RequestParam(value="subnet", required=false) String subnet,
			       @RequestParam(value="ethernet", required=false) String ethernet,
			       @RequestParam(value="options", required=false) String options,
			       @RequestParam(value="del", required=false) List<String>del,
			       HttpServletRequest request, HttpServletResponse response,
			       Model model) {

	// add or delete hosts

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
	    return subnetsController.subnetsGet(request, response, model);
	}

	Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	if (subject == null) {
	    messages.add("Session has expired");
	    model.addAttribute("messages", messages);
	    return loginController.loginGet("dhcp", request, response, model); 
	}

	// delete hosts

	if (del != null && del.size() > 0) {

	    DirContext ctx = null;

	    
	    // list of hosts to delete. do them one by one
	    // have to find them first
	    for (String d: del) {
		var action = new common.JndiAction(new String[]{"(&(objectclass=dhcphost)(cn=" + d + "))", conf.dhcpbase, "dn"});
		// reuse existing context when doing repeated opertions
		if (ctx != null)
		    action.ctx = ctx;
		action.noclose = true;

		Subject.doAs(subject, action);
		ctx = action.ctx;
		
		var hosts = action.data;
		// should be just one
		if (hosts != null && hosts.size() > 0) {
		    var dn = lu.oneVal(hosts.get(0).get("dn"));

		    try {
			ctx.destroySubcontext(dn);
		    } catch (javax.naming.NamingException e) {
			messages.add("Unable to delete " + d + ": " + e.toString());
			model.addAttribute("messages", messages);
		    }

		}
	    }

	    try {
		if (ctx != null)
		    ctx.close();
	    } catch (Exception ignore) {
	    }
	}

	// if no name specified, nothing more to do
	if (name == null || "".equals(name.trim()))
	    return hostsGet(subnet, request, response, model);

	name = name.trim();

	InetAddress[] addresses;

	System.out.println("name " + name);

	try {
	    addresses = InetAddress.getAllByName(name);
	} catch (UnknownHostException e) {
	    messages.add("Hostname not found");
	    model.addAttribute("messages", messages);
	    return hostsGet(subnet, request, response, model);
	}

	if (addresses.length < 1) {
	    messages.add("No addresses for ostname");
	    model.addAttribute("messages", messages);
	    return hostsGet(subnet, request, response, model);
	}

	// adding is easy. The problem is we have to add it within the group
	// representing the subnet. finding the group based on the IP address isn't easy

	// Since we don't know what masks may be used by subnets, and the name is in
	// octets, some trial and error is needed. For the moment we just look at all
	// groups and see which one matches. The hope is that addition isn't done
	// that often.

	var action = new common.JndiAction(new String[]{"(objectclass=dhcpgroup)", conf.dhcpbase, "cn", "dn", "dhcpoption"});

	System.out.println("point 1");
	// save the context for the addition
	action.noclose = true;
	Subject.doAs(subject, action);
	var ctx = action.ctx;
			
	var groups = action.data;
	if (groups == null) {
	    messages.add("Please add the subnet before adding hosts");
	    model.addAttribute("messages", messages);
	    return hostsGet(subnet, request, response, model);
	}

	// this is going to be the dn of the new host. starts as subnet dn
	String dn = null;

	System.out.println("point 2");
	for (var group: groups) {
	    var cn = lu.oneVal(group.get("cn"));
	    String mask = null;
	    // cn should be a subnet name. need subnet mask
	    for (var option: lu.valList(group.get("dhcpoption")))
		if (option.toLowerCase().startsWith("subnet-mask"))
		    mask = option.substring(11).trim();

	    // not a usable subnet without a mask
	    if (mask == null)
		continue;

	    System.out.println("cn " + cn + " mask " + mask);
	    SubnetUtils subnetu = null;
	    try {
		subnetu = new SubnetUtils(cn, mask);
	    } catch (IllegalArgumentException ignore) {
		// ignore groups that don't look like subnets
		continue;
	    }

	    var subnetInfo = subnetu.getInfo();
	    // OK. Now look for everything in that range.

	    if (subnetInfo.isInRange(addresses[0].getHostAddress())) {
		// found it
		dn = lu.oneVal(group.get("dn"));
		break;
	    }

	}
	System.out.println("point 3");
	if (dn == null) {
	    messages.add("Please add the subnet before adding hosts");
	    model.addAttribute("messages", messages);
	    return hostsGet(subnet, request, response, model);
	}

	// we now have data for the new host in the variables from
	// the form, and the dn to add it under in subnet
	// a DirContext is left over in ctx from the search

	// create the new host entry

	System.out.println("point 4");
	var oc = new BasicAttribute("objectClass");
	oc.add("top");
	oc.add("dhcpHost");

	// have container, i.e. subnet; make the real dn
	dn = "cn=" + name + "," + dn;

	var cn = new BasicAttribute("cn", name);
	var dhcpHWAddress = new BasicAttribute("dhcpHWAddress", "ethernet " + ethernet);
	var addrstatement = "fixed-address";
	for (var address: addresses)
	    addrstatement = addrstatement + " " + address.getHostAddress();;

	var dhcpStatements = new BasicAttribute("dhcpStatements", addrstatement);

	var entry = new BasicAttributes();
	entry.put(oc);
	entry.put(cn);
	entry.put(dhcpHWAddress);
	entry.put(dhcpStatements);

	if (options != null && ! options.isBlank()) {
	    var dhcpOption = new BasicAttribute("dhcpOption");
	    var lines = options.split("\n");
	    for (var line: lines)
		dhcpOption.add(line.trim());
	    entry.put(dhcpOption);
	}

	try {
	    var newctx = ctx.createSubcontext(dn, entry);
	    newctx.close();
	} catch (Exception e) {
	    messages.add("Can't create new entry: " + e.toString());
	    model.addAttribute("messages", messages);
	    return subnetsController.subnetsGet(request, response, model); 
	} finally {
	    try {
		ctx.close();
	    } catch (Exception ignore) {}
	}

	if (subnet != null)
	    model.addAttribute("subnet", filtername(subnet));

	return hostsGet(subnet, request, response, model);

    }

}
