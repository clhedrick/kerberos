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
import java.util.Arrays;
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
	String ret = s.replaceAll("[^.0-9]","");
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

	// default filter -- all hosts
	// finding all hosts in a subnet is non-trivial. For it to work, we
	// need a fixedaddress option for all hosts. Otherwise we would have to look at all
	//   hosts and convert hostname to ip
	// furthermore, we can only do a text compare, which means we can't do an ldap
	//   query for the exact range. We convert the subnet to a prefix, do an ldap search
	//   on that, and then test which of the results are actually in the subnet
	// Another way to do this would be to add a lowaddress and highattress attribute to
	//   the subnet that is a 32-bit number, and a 32-bit address to each host.
	//   Then we could do an LDAP search for addresses >= low and < high. 
	var filter = "objectclass=dhcphost";
	if (subnet != null && !subnet.isBlank()) {
	    // user has passed subnet, parse it
	    SubnetUtils subnetu = null;
	    try {
		subnetu = new SubnetUtils(subnet);
	    } catch (IllegalArgumentException ignore) {
		List<String> messages = new ArrayList<String>();
		messages.add("Subnet must be in format n.n.n.n/d");
		model.addAttribute("messages", messages);
		return subnetsController.subnetsGet(request, response, model);
	    }

	    var subnetInfo = subnetu.getInfo();
	    // OK. Now look for everything in that range.

	    var i = subnet.indexOf("/");
	    var net = subnet.substring(0, i);
	    var bits = 0;
	    try {
		bits = Integer.parseInt(subnet.substring(i+1));
	    } catch (Exception impossible) {}

	    // bits is the CDIR suffix, e.g. 128.6.4.0/24 it's the 24

	    // Now create search term. For 128.6.4.0/24 it's 128.6.4.*
	    // But because it's a text compare, we have to use the same thing for 128.6.4.128/25.
	    // So any bits value from 24 to 31 gives us 128.6.4.*. Similarly for 16 to 23 it's 128.6.*
	    // the search wildcard, e.g. 128.6.4.* goes in "mask"

	    String mask;
	    if (bits < 8)
		mask = "*";
	    else {
		i = net.indexOf(".");
		if (bits < 16)
		    mask = net.substring(0, i+1) + "*";  // include the .
		else {
		    i = net.indexOf(".", i+1);
		    if (bits < 24)
			mask = net.substring(0, i+1) + "*";  // include the .			
		    else {
			i = net.indexOf(".", i+1);
			if (bits < 32)
			    mask = net.substring(0, i+1) + "*";  // include the .
			else
			    // /32 means an exact host, though it would be really
			    //   odd to have such a subnet
			    mask = net;
		    }
		}
	    }
	    
	    // now mask is something like 128.6.*
	    common.JndiAction action = new common.JndiAction(new String[]{"(&(objectclass=dhcphost)(dhcpStatements=fixed-address* " + mask + "))", conf.dhcpbase, "cn", "dhcphwaddress", "dhcpstatements", "dhcpoption"});
	    Subject.doAs(subject, action);

	    var hosts = action.data;
	    var entries = new ArrayList<Map<String,List<String>>>();
	    // we may have hosts not actually in the subnet because the LDAP search is approximate.
	    // So we need to test subnetInfo.isInRange(address) before we use the host
	    //   Add an address property to make sorting easier
	    if (hosts != null && hosts.size() > 0) {
		for (var host: hosts) {
		    var statements = host.get("dhcpstatements");
		    if (statements != null)
			for (var statement: statements) {
			    if (statement.startsWith("fixed-address")) {
				var addresslist = statement.substring("fixed-address".length() + 1);
				var addresses = addresslist.split("\\s+");
				for (var address: addresses) {
				    if (subnetInfo.isInRange(address)) {
					// only one address may match, but we should show them all when we show the host
					host.put("address", Arrays.asList(addresses)); // save for sort
					entries.add(host);
					break; // don't add host more than once
				    }
				}
			    }
			}
		}
		// now entries is all the hosts that match the subnet specification
		Collections.sort(entries, (g1, g2) -> g1.get("address").get(0).compareTo(g2.get("address").get(0)));

	    }
	    // set up model for JSTL to output

	    model.addAttribute("hosts", entries);
	    model.addAttribute("subnet", subnet);
	    model.addAttribute("dhcpmanager", (privs.contains("dhcpmanager")));
	    model.addAttribute("superuser", (privs.contains("superuser")));

	    return "/dhcp/showhosts";
	}

	// no subnet arg. all hosts
	common.JndiAction action = new common.JndiAction(new String[]{"(objectclass=dhcphost)", conf.dhcpbase, "cn", "dhcphwaddress", "dhcpstatements"});
	Subject.doAs(subject, action);

	var hosts = action.data;
	if (hosts != null && hosts.size() > 0) {
	    for (var host: hosts) {
		var statements = host.get("dhcpstatements");
		if (statements != null)
		    for (var statement: statements) {
			if (statement.startsWith("fixed-address")) {
			    var addresslist = statement.substring("fixed-address".length() + 1);
			    var addresses = addresslist.split("\\s+");
			    var addrs = new ArrayList<String>();
			    for (var addr: addresses)
				addrs.add(addr);
			    host.put("address", addrs); // save for sort
			}
		    }
	    }
	    // now entries is all the hosts that match the subnet specification
	    Collections.sort(hosts, (g1, g2) -> g1.get("address").get(0).compareTo(g2.get("address").get(0)));
	}

	model.addAttribute("subnet", subnet);
	model.addAttribute("hosts", hosts);
	model.addAttribute("dhcpmanager", (privs.contains("dhcpmanager")));
	model.addAttribute("superuser", (privs.contains("superuser")));

	return "/dhcp/showhosts";	
		
    }

    @PostMapping("/dhcp/showhosts")
    public String subnetsSubmit(@RequestParam(value="names[]", required=false) String[] names,
			       @RequestParam(value="subnet", required=false) String subnet,
			       @RequestParam(value="ethernet[]", required=false) String[] ethernets,
			       @RequestParam(value="options[]", required=false) String[] optionss,
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
	    return subnetsController.subnetsGet(request, response, model);
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

	    try {
		ctx.close();
	    } catch (Exception ignore) {
	    }
	}

	System.out.println("names " + names);

	// if no name specified, nothing more to do
	if (names == null || names.length == 0)
	    return hostsGet(subnet, request, response, model);

	DirContext ctx = null;
	for (var newi = 0; newi < names.length; newi++) {

	    // arrays get null elements if nothing there
	    // but omit null elements if they are at the end
	    // of the array. so if beyond the end, assume null
	    String name = names[newi];
	    if (name == null)
		continue;
	    String ethernet = null;
	    if (ethernets.length >  newi)
		ethernet = ethernets[newi];
	    String options = null;
	    if (optionss.length > newi)
		options = optionss[newi];

	    name = name.trim();

	    InetAddress[] addresses;

	    try {
		addresses = InetAddress.getAllByName(name);
	    } catch (UnknownHostException e) {
		messages.add("Hostname not found");
		model.addAttribute("messages", messages);
		return hostsGet(subnet, request, response, model);
	    }

	    Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	    if (subject == null) {
		messages.add("Session has expired");
		model.addAttribute("messages", messages);
		return loginController.loginGet("dhcp", request, response, model); 
	    }

	    if (ethernet == null || ! ethernet.matches("\\p{XDigit}\\p{XDigit}:\\p{XDigit}\\p{XDigit}:\\p{XDigit}\\p{XDigit}:\\p{XDigit}\\p{XDigit}:\\p{XDigit}\\p{XDigit}:\\p{XDigit}\\p{XDigit}")) {
		messages.add("Ethernet address must be of form xx:xx:xx:xx:xx:xx");
		model.addAttribute("messages", messages);
		return hostsGet(subnet, request, response, model);
	    }

	    // no filter, so no search. this is just to get a context
	    common.JndiAction action = new common.JndiAction(new String[]{null, conf.dhcpbase});

	    action.ctx = ctx;
	    action.noclose = true;
	    
	    Subject.doAs(subject, action);
	    
	    ctx = action.ctx;
	    
	    var oc = new BasicAttribute("objectClass");
	    oc.add("top");
	    oc.add("dhcpHost");

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

	    var dn = "cn=" + name + ",cn=config," + conf.dhcpbase;
	    try {
		var newctx = ctx.createSubcontext(dn, entry);
		newctx.close();
	    } catch (Exception e) {
		try {
		    ctx.close();
		} catch (Exception ignore) {}
		messages.add("Can't create new entry: " + e.toString());
		model.addAttribute("messages", messages);
		return subnetsController.subnetsGet(request, response, model); 
	    }
	    
	}
	try {
	    ctx.close();
	} catch (Exception ignore) {}	    
	return hostsGet(subnet, request, response, model);

    }

}
