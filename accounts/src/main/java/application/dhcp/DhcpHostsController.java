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

// show hosts in a subnet, or based on a search, and let them be edited.
// this is the core of the DHCP application.

import org.ietf.jgss.GSSCredential;
import java.util.List;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.Calendar;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Comparator;
import java.math.BigInteger;
import java.text.SimpleDateFormat;
import java.net.UnknownHostException;
import java.net.InetAddress;
import java.net.Inet4Address;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.ApplicationContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
import Activator.Db;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.commons.net.util.SubnetUtils;

@Controller
public class DhcpHostsController {

    @Lazy
    @Autowired
    private LoginController loginController;

    @Autowired
    private SubnetsController subnetsController;

    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^-_a-zA-Z.:0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    // from the conversion process we sometimes have an entry
    // with two cns. One is the hostname. The other (which is
    // used for the dn) has a number on the end to make it unique
    public void fixCn(Map<String,List<String>> host) {
	if (host.get("cn").size() > 1) {
	    // this is that weird case. reset cn from dn
	    var dn = lu.oneVal(host.get("dn"));
	    // cn=jjj,...
	    var i = dn.indexOf(",");
	    var cn = dn.substring(3, i);
	    host.put("cn", List.of(cn));
	}
    }

    // for sorting ip addresss. Take an LDAP entry, get the address attribute
    // (which can be either "address" or "cn", so we pass the attribute as an arg).
    // convert to a BigInteger for sorting.
    public static BigInteger getIntAddress(Map<String,List<String>> entry, String property) {
	try {
	    var ipAddress = entry.get(property).get(0);
	    return new BigInteger(1, InetAddress.getByName(ipAddress).getAddress());
	} catch (Exception ignore) {
	    return new BigInteger("0");
	}
    }

    // users can enter ethernet addresses in all sorts of formats
    // the usual is 00:11:22:33:44:55. But some people use
    // 3 components, e.g. 0011.2233.4455. Separators can be
    // : . - and even space. Figure out which of these they
    // used and convert to the standard.
    public String normalizeEthernet(String ethernet) {
	if (ethernet == null)
	    return null;
	ethernet = ethernet.toLowerCase();
	// let's assume consistent punctuation. What did they use?
	String separator = null;
	long count = 0;
	if ((count = ethernet.chars().filter(ch -> ch == ':').count()) > 0)
	    separator = ":";
	else if ((count = ethernet.chars().filter(ch -> ch == '-').count()) > 0)
	    separator = "-";
	else if ((count = ethernet.chars().filter(ch -> ch == '.').count()) > 0)
	    separator = ".";
	else if ((count = ethernet.chars().filter(ch -> ch == ' ').count()) > 0)
	    separator = " ";
	// only reasonable numbers are 2 and 5, representing 3 or 6 components
	if (count == 2 || count == 5) {
	    // compute number of digits in each component
	    int digits = 2;
	    if (count == 2)
		digits = 4;
	    String[] pieces = ethernet.split("\\" + separator);
	    // pad the components with 0 if necessary
	    for (int i = 0; i <= count; i++) {
		// if leading zeros are missing, supply them
		if (pieces[i].length() < digits) {
		    pieces[i] = "0000".substring(0, digits - pieces[i].length()) + pieces[i];
		}
	    }
	    // we now have it without any punctuation
	    ethernet = ethernet.join("", pieces);
	} 
	// for anything valid we now have 12 digits
	if (! ethernet.matches("\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}\\p{XDigit}")) {
	    return null;
	}
	// put it in the format dhcp wants
	ethernet = ethernet.substring(0,2) + ":"
	    + ethernet.substring(2,4) + ":"
	    + ethernet.substring(4,6) + ":"
	    + ethernet.substring(6,8) + ":"
	    + ethernet.substring(8,10) + ":"
	    + ethernet.substring(10,12);
	return ethernet;
    }

    public String hostsGet(Integer ifid, HttpServletRequest request, HttpServletResponse response, Model model) {
	return hostsGet(null, null, null, null, ifid, request, response, model);
    }

    // lots of optional arguments for the search operation. Only one argument will
    // normally be specified. The page has to pass the arg on in hidden INPUTs, so
    // we'll consistently show the same data when editing.
    @GetMapping("/dhcp/showhosts")
    public String hostsGet(@RequestParam(value="subnet", required=false) String subnet,
			   @RequestParam(value="host", required=false) String hostname,
			   @RequestParam(value="ip", required=false) String ipaddress,
			   @RequestParam(value="ether", required=false) String etheraddress,
			   @RequestParam(value="ifid", required=false) Integer ifid,
			   HttpServletRequest request, HttpServletResponse response, Model model) {
	// This module uses Kerberized LDAP. The credentials are part of a Subject, which is stored in the session.
	// This JndiAction junk is needed to execute the LDAP code in a context that's authenticated by
	// that Subject.

	Config conf = Config.getConfig();
	var privs = (Set<?>)request.getSession().getAttribute("privs");
	
	Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	if (subject == null) {
	    List<String> messages = new ArrayList<String>();
	    messages.add("Session has expired");
	    model.addAttribute("messages", messages);
	    return loginController.loginGet("dhcp", ifid, request, response, model); 
	}
	GSSCredential  gssapi = (GSSCredential)request.getSession().getAttribute("gssapi");

	// default filter is all hosts


	// the first code is when the user specifies a subnet. This is complex.
	// finding all hosts in a subnet is non-trivial. For it to work, we
	// need a fixedaddress option for all hosts. Otherwise we would have to look at all
	//   hosts and convert hostname to ip
	// furthermore, LDAP queries only allow a text compare, which means we can't do an ldap
	//   query for the exact range. We convert the subnet to a prefix that may be larger
	//   than the actual subnet, do an ldap search
	//   on that, and then test which of the results are actually in the subnet
	// Another way to do this would be to add a lowaddress and highattress attribute to
	//   the subnet that is a 32-bit number, and a 32-bit address to each host.
	//   Then we could do an LDAP search for addresses >= low and < high. 
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
	    common.JndiAction action = new common.JndiAction(gssapi, new String[]{"(&(objectclass=dhcphost)(dhcpStatements=fixed-address* " + mask + "))", conf.dhcpbase, "cn", "dhcphwaddress", "dhcpstatements", "dhcpoption", "dn"});
	    Subject.doAs(subject, action);

	    var hosts = action.data;
	    var entries = new ArrayList<Map<String,List<String>>>();
	    // we may have hosts not actually in the subnet because the LDAP search is approximate.
	    // So we need to test subnetInfo.isInRange(address) before we use the host
	    //   Add an address property to make sorting easier
	    if (hosts != null && hosts.size() > 0) {
		for (var host: hosts) {
		    // the address is stored as a fixed-address statement
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
					fixCn(host);
					entries.add(host);
					break; // don't add host more than once
				    }
				}
			    }
			}
		}
		// now entries is all the hosts that match the subnet specification
		Collections.sort(entries, (g1, g2) -> getIntAddress(g1, "address").compareTo(getIntAddress(g2, "address")));

	    }
	    // set up model for JSTL to output

	    model.addAttribute("ifid", ifid);
	    model.addAttribute("hosts", entries);
	    model.addAttribute("subnet", subnet);
	    model.addAttribute("dhcpmanager", (privs.contains("dhcpmanager")));
	    model.addAttribute("superuser", (privs.contains("superuser")));

	    // hmmm. the model is actually ignored
	    return "/dhcp/showhosts";
	}


	
	// no subnet arg. all hosts or a search
	// Default is all hosts, but see if the user specified a search term.
	var filter = "objectclass=dhcphost";
	if (ifid != null) {
	    filter = "(&(objectclass=dhcphost)(dhcpcomments=" + ifid.toString() + "))";
	} else if (hostname != null && !hostname.isBlank()) {
	    var name = filtername(hostname.trim());
	    model.addAttribute("host", name);
	    filter = "(&(objectclass=dhcphost)(|(cn=" + name + ")(dhcpoption=host-name \"" + name + "\")))";
	} else if (ipaddress != null && !ipaddress.isBlank()) {
	    var name = filtername(ipaddress.trim());
	    model.addAttribute("ip", name);
	    filter = "(&(objectclass=dhcphost)(dhcpStatements=fixed-address " + name + "))";
	} else if (etheraddress != null && !etheraddress.isBlank()) {
	    var name = normalizeEthernet(etheraddress.trim());
	    if (name == null) {
		List<String> messages = new ArrayList<String>();
		messages.add("Invalid Ethernet address, try aa:bb:cc:dd:ee:ff, but any standard format will work");
		model.addAttribute("messages", messages);
		return subnetsController.subnetsGet(request, response, model);
	    }
	    model.addAttribute("ether", name);
	    filter = "(&(objectclass=dhcphost)(dhcpHWAddress=ethernet*" + name + "))";
	}

	common.JndiAction action = new common.JndiAction(gssapi, new String[]{filter, conf.dhcpbase, "cn", "dhcphwaddress", "dhcpstatements", "dhcpoption", "dn"});
	Subject.doAs(subject, action);

	var hosts = action.data;
	// if we came from inventory and didn't find anything linked
	// to this interface, try to find it
	if ((hosts == null || hosts.size() == 0) && ifid != null) {
	    var db = new Db();
	    db.openDb(conf);
	    var ether = db.findEtherForIf(ifid, conf);
	    if (ether == null || ether.isBlank()) {
		List<String> messages = new ArrayList<String>();
		messages.add("no ethernet address for inventory entry. No way to handle this");
		model.addAttribute("messages", messages);
		return "/dhcp/showhosts";
	    }
	    db.closeDb();
	    filter = "(&(objectclass=dhcphost)(dhcpHWAddress=ethernet*" + ether.toLowerCase() + "))";
	    common.JndiAction ifaction = new common.JndiAction(gssapi, new String[]{filter, conf.dhcpbase, "cn", "dhcphwaddress", "dhcpstatements", "dhcpoption", "dhcpcomments", "dn"});
	    ifaction.noclose = true; // so we can do modify

	    Subject.doAs(subject, ifaction);
	    var ctx = ifaction.ctx;

	    hosts = ifaction.data;
	    if (hosts != null && hosts.size() == 1) {
		// found just one host with this ether. link it to inventory
		var host = hosts.get(0);
		List<String> messages = new ArrayList<String>();

		var comment = new BasicAttribute("dhcpcomments", ifid.toString());
		var entry = new BasicAttributes();
		entry.put(comment);

		var op = DirContext.ADD_ATTRIBUTE;
		if (lu.hasVal(host.get("dhcpcomments")))
		    op = DirContext.REPLACE_ATTRIBUTE;
		try {
		    ctx.modifyAttributes(lu.oneVal(host.get("dn")), op, entry);
		} catch (javax.naming.NamingException e) {
		    messages.add("Unable to link this DHCP entry to the inventory entry: " + e.toString());
		    model.addAttribute("messages", messages);
		}

		// go ahead and display entry
		// user can modify it if necessary

		messages.add("We found exactly one DHCP entry with this ethernet address. We've linked it to this inventory entry, so its data will show there after the next nightly update.");
		model.addAttribute("messages", messages);

	    } else if (hosts != null && hosts.size() >= 1) {
		List<String> messages = new ArrayList<String>();
		messages.add("More than one DHCP entry has the Ethernet address specified. Please edit and save the one for the inventory entry you came from. That will link the DHCP entry with this inventory entry. Its data will show in inventory after the next nightly update. It's OK to leave the other entries if they're valid, but the one you pick will have its hostname and IP displayed in the inventory.");
		model.addAttribute("messages", messages);
		// add this so we'll link it
		model.addAttribute("ifid", ifid);
	    } else if (hosts == null || hosts.size() == 0) {
		List<String> messages = new ArrayList<String>();
		messages.add("We haven't found anything in DHCP with this Ethernet address. If you add one, it will be linked to this inventory entry. Its data will show in inventory after the next nightly update.");
		model.addAttribute("messages", messages);

		// nothing found. will display add screen
		// prefill ethernet address
		model.addAttribute("newether", ether);
		// send the ifid so it will link up when added
		model.addAttribute("ifid", ifid);
	    }
	    try {
		ctx.close();
	    } catch (Exception e) {}
	}
	if (hosts != null && hosts.size() > 0) {
	    for (var host: hosts) {
		var statements = host.get("dhcpstatements");
		if (statements != null)
		    for (var statement: statements) {
			// have to get its IP address for sorting
			// it is stored as a fixed-address statement
			if (statement.startsWith("fixed-address")) {
			    var addresslist = statement.substring("fixed-address".length() + 1);
			    var addresses = addresslist.split("\\s+");
			    var addrs = new ArrayList<String>();
			    for (var addr: addresses)
				addrs.add(addr);
			    host.put("address", addrs); // save for sort
			    fixCn(host);
			}
		    }
	    }
	    // now entries is all the hosts that match the subnet specification
	    Collections.sort(hosts, (g1, g2) -> getIntAddress(g1, "address").compareTo(getIntAddress(g2, "address")));
	}

	model.addAttribute("subnet", subnet);
	model.addAttribute("hosts", hosts);
	model.addAttribute("dhcpmanager", (privs.contains("dhcpmanager")));
	model.addAttribute("superuser", (privs.contains("superuser")));

	return "/dhcp/showhosts";	
		
    }

    // update one or more hosts
    // subnet, host, ip, and ether are search terms. They are passed
    // through the web page as hidden variables so that when we finally
    // display the results we use the same host list as the original display
    
    // The rest are fields in the host definition that can be updated.
    // They are all arrays, because more then one host can be updated at a time.
    

    @PostMapping("/dhcp/showhosts")
    public String subnetsSubmit(@RequestParam(value="names[]", required=false) String[] names,
			       @RequestParam(value="subnet", required=false) String subnet,
			       @RequestParam(value="host", required=false) String hostname,
			       @RequestParam(value="ip", required=false) String ipaddress,
			       @RequestParam(value="ether", required=false) String etheraddress,
			       @RequestParam(value="ifid", required=false) Integer ifid,
			       @RequestParam(value="ethernet[]", required=false) String[] ethernets,
			       @RequestParam(value="ip[]", required=false) String[] ips,
			       @RequestParam(value="origname[]", required=false) String[] orignames,
			       @RequestParam(value="options[]", required=false) String[] optionss,
			       @RequestParam(value="del", required=false) List<String>del,
			       HttpServletRequest request, HttpServletResponse response,
			       Model model) {

	List<String>messages = new ArrayList<String>();
	model.addAttribute("messages", messages);
	((List<?>)model.asMap().get("messages")).clear();

	Logger logger = null;
	logger = LogManager.getLogger();

	Config conf = Config.getConfig();
	var privs = (Set<?>)request.getSession().getAttribute("privs");


	// user has asked to modify subnets but doesn't have permission
	if (!(privs.contains("dhcpmanager")) && !(privs.contains("superuser"))) {
	    messages.add("You don't have permission to manage DHCP");
	    model.addAttribute("messages", messages);
	    return subnetsController.subnetsGet(request, response, model);
	}

	// first see if any hosts are being deleted

	if (del != null && del.size() > 0) {
	    Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	    GSSCredential gssapi = (GSSCredential) request.getSession().getAttribute("gssapi");
	    
	    if (subject == null) {
		messages.add("Session has expired");
		model.addAttribute("messages", messages);
		return loginController.loginGet("dhcp", ifid, request, response, model); 
	    }

	    // normally JndiAction opens a connection to LDAP, does a query, and
	    // closes the connection. We are potentially going to do lots of LDAP
	    // operations, so we open the connection once and keep it open.
	    // This call has no filter, so it doesn't do a search, but it does
	    // open the connection.
	    // If you specify noclose, it won't be closed at the end of the operation.
	    // Other calls to JndiAction will need to specify noclose as well,
	    // and we'll do an explicit close at the end
	    common.JndiAction action = new common.JndiAction(gssapi, new String[]{null, conf.dhcpbase});
	    action.noclose = true;

	    Subject.doAs(subject, action);

	    // the whole point of this call was to open an LDAP connection.
	    // In JNDI terms, that's a context. So save the context.
	    // Future calls to JndiAction will insert this context and
	    // specify noclose. Then it will be closed explicitly.
	    var ctx = action.ctx;

	    for (String d: del) {
		var dn = "cn=" + d + ",cn=config," + conf.dhcpbase;
		try {
		    // this is the JNDI approach to deleting an LDAP entry
		    ctx.destroySubcontext(dn);
		    logger.info("DHCP: deleted entry " + d);
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

	// if no name specified, nothing more to do
	// if there's a name, we have hosts to update
	if (names == null || names.length == 0)
	    return hostsGet(subnet, hostname, ipaddress, etheraddress, ifid, request, response, model);

	// if we're here there are new hosts or hosts to be updated.
	// so we can tell the difference, the original entry name (cn)
	// is passed in origname when an existing entry is updated.
	// otherwise it's a new entry

	DirContext ctx = null;
	mainloop:
	// loop over hosts that might be updated.
	// this is complicated because the attribute values
	// as sent as arrays. They match. I.e. name[1] and
	// ethernets[1] are for the same host. However
	// the arrays can be of different length. In that
	// case the values beyond the end of an array are
	// effectively blank. So in the loop each attribute
	// gets the values from the array if it exists,
	// else null.
	for (var newi = 0; newi < names.length; newi++) {

	    // can't do anything if there's no entry name
	    String name = names[newi];
	    if (name == null || name.isBlank())
		continue;
	    name = name.trim();
	    if (! name.equals(filtername(name))) {
		messages.add("Illegal hostname: " + name);
		model.addAttribute("messages", messages);
		continue;
	    }

	    String ethernet = null;
	    if (ethernets.length >  newi)
		ethernet = ethernets[newi];

	    String options = null;
	    if (optionss.length > newi)
		options = optionss[newi];

	    String ip = null;
	    if (ips.length > newi)
		ip = ips[newi];

	    String origname = null;
	    if (orignames.length > newi)
		origname = orignames[newi];

	    Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	    GSSCredential gssapi = (GSSCredential)request.getSession().getAttribute("gssapi");
	    
	    if (subject == null) {
		messages.add("Session has expired");
		model.addAttribute("messages", messages);
		return loginController.loginGet("dhcp", ifid, request, response, model); 
	    }

	    ethernet = normalizeEthernet(ethernet);
	    if (ethernet == null) {
		messages.add("Invalid Ethernet address. Try format aa:bb:cc:dd:ee:ff, although other formats also work");
		model.addAttribute("messages", messages);
		continue;
	    }

	    // there can be multiple IP addresses. If so, make sure
	    // they're all legal and create an appropriate fixed-address statement for
	    // the LDAP entry
	    var addrstatement = "fixed-address";
	    if (ip !=  null && !ip.isBlank()) {
		var addrs = ip.split(",");
		for (var addr: addrs) {
		    addr = addr.trim();
		    if (addr.isBlank())
			continue;
		    // make sure it's legal. there's tnothingin InetAddress to parse numerical
		    try {
			var subnetu = new SubnetUtils(addr, "255.255.255.255");
		    } catch (IllegalArgumentException ignore) {
			messages.add("IP address must be in format n.n.n.n");
			model.addAttribute("messages", messages);
			continue mainloop;
		    }
		    addrstatement = addrstatement + " " + addr;
		}
	    } else {
		// if no IP addresses are specified, use the one
		// from the hostname

		InetAddress[] addresses;

		try {
		    addresses = InetAddress.getAllByName(name);
		} catch (UnknownHostException e) {
		    messages.add("Hostname not found");
		    model.addAttribute("messages", messages);
		    continue;
		}

		for (var address: addresses) {
		    // skip ipv6 addresses, since DHCP only handles v4
		    if (address instanceof java.net.Inet4Address) {
			var addressstr = address.getHostAddress();
			addrstatement = addrstatement + " " + addressstr;
		    }
		}
	    }

	    if (origname != null && !origname.isBlank()) {
		// edit existing item
		var logmsg = "";

		common.JndiAction action = new common.JndiAction(gssapi, new String[]{"(&(objectclass=dhcphost)(cn="+ filtername(origname) + "))", conf.dhcpbase, "cn", "dhcphwaddress", "dhcpstatements", "dhcpoption", "dn"});

		// If there is an existing connection, use it
		action.ctx = ctx;
		// If we open a connection (which we will the first time, when ctx is null)
		// don't close it, so any further queries use the same connection.
		action.noclose = true;
		Subject.doAs(subject, action);

		var hosts = action.data;

		// now save the connection for further activity
		ctx = action.ctx;

		if (hosts.size() != 1) {
		    messages.add("Trying to edit " + filtername(origname) + " but does not exist or is not unique");
		    model.addAttribute("messages", messages);
		    continue;
		}

		var host = hosts.get(0);
		var changed = false;
		
		// now see if anything has changed.
		// if so set changed to true
		// entry will be used to create an LDAP modify command
		// only attributes in the entry will be changed.
		// so if the new value is different from the old
		// we set put the new value in entry
	 
		var entry = new BasicAttributes();
		if (! lu.valList(host.get("dhcpstatements")).contains(addrstatement)) {
		    changed = true;
		    var dhcpStatements = new BasicAttribute("dhcpStatements", addrstatement);
		    entry.put(dhcpStatements);
		}
		logmsg += " " + addrstatement;
	    
		ethernet = normalizeEthernet(ethernet);
		if (ethernet == null) {
		    messages.add("Invalid Ethernet address. Try format aa:bb:cc:dd:ee:ff, although other formats also work");
		    model.addAttribute("messages", messages);
		}
		var etherval = "ethernet " + ethernet;
		if (! etherval.equals(lu.oneVal(host.get("dhcphwaddress")))) {
		    changed = true;
		    var dhcpHWAddress = new BasicAttribute("dhcpHWAddress", etherval);
		    entry.put(dhcpHWAddress);
		}
		logmsg += " " + etherval;

		// comparing old and new options is more complex, because there
		// can be more than one and they can be in different order. We
		// need a Set so we can compare. They might be in different order
		// but when you compare sets, java ignores differences in order
		var oldOptions = new HashSet<String>(lu.valList(host.get("dhcpoption")));
		var newOptions = new HashSet<String>();
		var lines = options.split("\n");

		for (var line: lines)
		    if (! line.trim().isBlank()) {
			newOptions.add(line.trim());
			logmsg += " " + line.trim();
		    }

		if (! oldOptions.equals(newOptions)) {
		    changed = true;

		    // if options have changed, add all of the new
		    // ones to the entry to be used for modify
		    var dhcpOption = new BasicAttribute("dhcpOption");
		    for (var line: lines)
			if (! line.trim().isBlank())
			    dhcpOption.add(line.trim());
		    entry.put(dhcpOption);
		}

		if (ifid != null) {
		    var comments = new BasicAttribute("dhcpComments", ifid.toString());
		    entry.put(comments);
		    changed = true;
		}

		// now, if at least one thing changed, do an LDAP modify
		if (changed) {
		    try {
			var dhcpOption = new BasicAttribute("dhcpOption");
			ctx.modifyAttributes(lu.oneVal(host.get("dn")), DirContext.REPLACE_ATTRIBUTE, entry);
			logger.info("DHCP: modified entry " + origname + ":" + logmsg);
		    } catch (Exception e) {
			messages.add("Unable to change " + filtername(origname) + ": " + e.toString());
			model.addAttribute("messages", messages);
			continue;
		    }
		}

		// if name and origname are different, the entry has been renamed
		// That means changing the "cn". 
		if (! origname.equals(name) && name != null && !name.isBlank()) {
		    var newdn = "cn=" + name + ",cn=config," + conf.dhcpbase;
		    try {
			ctx.rename(lu.oneVal(host.get("dn")), newdn);
			logger.info("DHCP: renamed entry " + origname + " to " + name);
		    } catch (Exception e) {
			messages.add("Unable to rename " + filtername(origname) + " to " + name + ": " + e.toString());
			model.addAttribute("messages", messages);
			continue;
		    }
			
		}

		continue;

	    }

	    // not edit, so adding new item

	    // no filter, so no search. this is just to get a context
	    common.JndiAction action = new common.JndiAction(gssapi, new String[]{null, conf.dhcpbase});

	    // use existing LDAP connection if there is one
	    action.ctx = ctx;
	    // don't close connection
	    action.noclose = true;
	    
	    Subject.doAs(subject, action);
	    
	    ctx = action.ctx;

	    var logmsg = "";

	    var oc = new BasicAttribute("objectClass");
	    oc.add("top");
	    oc.add("dhcpHost");

	    var cn = new BasicAttribute("cn", name);
	    var dhcpHWAddress = new BasicAttribute("dhcpHWAddress", "ethernet " + ethernet);
	    var dhcpStatements = new BasicAttribute("dhcpStatements", addrstatement);
	    logmsg += " " + addrstatement + " ethernet " + ethernet;
	    
	    var entry = new BasicAttributes();
	    entry.put(oc);
	    entry.put(cn);
	    entry.put(dhcpHWAddress);
	    entry.put(dhcpStatements);

	    if (ifid != null) {
		var comment = new BasicAttribute("dhcpComments", ifid.toString());
		entry.put(comment);
	    }

	    if (options != null && ! options.isBlank()) {
		var dhcpOption = new BasicAttribute("dhcpOption");
		var lines = options.split("\n");
		for (var line: lines) {
		    dhcpOption.add(line.trim());
		    logmsg += " " + line.trim();
		}
		entry.put(dhcpOption);
	    }

	    var dn = "cn=" + name + ",cn=config," + conf.dhcpbase;
	    try {
		var newctx = ctx.createSubcontext(dn, entry);
		newctx.close();
		logger.info("DHCP: added enty " + name + ":" + logmsg);
	    } catch (Exception e) {
		try {
		    ctx.close();
		} catch (Exception ignore) {}
		messages.add("Can't create new entry: " + e.toString());
		model.addAttribute("messages", messages);
		return subnetsController.subnetsGet(request, response, model); 
	    }
	    
	}

	// finally, we can close any LDAP connection we opened

	try {
	    ctx.close();
	} catch (Exception ignore) {}	    
	return hostsGet(subnet, hostname, ipaddress, etheraddress, ifid, request, response, model);

    }

}
