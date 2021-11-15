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

import org.ietf.jgss.GSSCredential;
import java.util.List;
import java.util.Collections;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.Calendar;
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
public class GroupsController {

    @Autowired
    private LoginController loginController;

    @Autowired
    private GroupController groupController;


    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^-_.a-z0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    @GetMapping("/groups/showgroups")
    public String groupsGet(HttpServletRequest request, HttpServletResponse response, Model model) {
	// This module uses Kerberized LDAP. The credentials are part of a Subject, which is stored in the session.
	// This JndiAction junk is needed to execute the LDAP code in a context that's authenticated by
	// that Subject.

	
	Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	if (subject == null) {
	    List<String> messages = new ArrayList<String>();
	    messages.add("Session has expired");
	    model.addAttribute("messages", messages);
	    return loginController.loginGet("group", request, response, model); 
	}

	// I use an API I wrote around Sun's API support.
	// See comments on showgroup.jsp

	String user = (String)request.getSession().getAttribute("krb5user");
	GSSCredential gssapi = (GSSCredential)request.getSession().getAttribute("gssapi");

	String query = Activator.Config.getConfig().groupsownedfilter.replaceAll("%u", user);

	// this action isn't actually done until it's called by doAs. That executes it for the Kerberos subject using GSSAPI
	common.JndiAction action = new common.JndiAction(gssapi, new String[]{query, "", "cn", "member", "dn", "gidNumber", "businessCategory", "dateofcreate", "createTimestamp"});

	Subject.doAs(subject, action);

	Set<?>privs = (Set<?>)request.getSession().getAttribute("privs");
	if (action.val.size() == 0 && !(privs.contains("addgroup"))) {
	    List<String> messages = new ArrayList<String>();
	    messages.add("There are no groups you can manage");
	    model.addAttribute("messages", messages);
	}

	// look at the results of the LDAP query
	List<Map<String, List<String>>> groups = action.data;
	Collections.sort(groups, (g1, g2) -> g1.get("cn").get(0).compareTo(g2.get("cn").get(0)));

	SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
	format.setTimeZone(TimeZone.getTimeZone("UTC"));

	// reviewdate for group is a year after creation
	// if now is after the review date, set needsreview
	for (Map<String, List<String>>group: groups) {
	    if (utils.needsReview(group))
		group.put("needsreview", new ArrayList<String>());
	}

	// set up model for JSTL to output
	model.addAttribute("groups", groups);
	model.addAttribute("canaddgroup", (privs.contains("addgroup")));
	model.addAttribute("isloginmanager", (privs.contains("loginmanager")));
	model.addAttribute("superuser", (privs.contains("superuser")));

        return "groups/showgroups";
    }

    @PostMapping("/groups/showgroups")
    public String groupsSubmit(@RequestParam(value="name", required=false) String name,
			       @RequestParam(value="sharing", required=false) String sharingSt,
			       @RequestParam(value="guests", required=false) String guestSt,
			       @RequestParam(value="del", required=false) List<String>del,
			       HttpServletRequest request, HttpServletResponse response,
			       Model model) {

	List<String>messages = new ArrayList<String>();
	model.addAttribute("messages", messages);
	((List<?>)model.asMap().get("messages")).clear();

	Logger logger = null;
	logger = LogManager.getLogger();

	Config conf = Config.getConfig();

	Set<?>privs = (Set<?>)request.getSession().getAttribute("privs");
	// user has asked to add group but doesn't have permission
	// actually, the ACIs should prohibit this anyway
	if (name != null && !"".equals(name) && !(privs.contains("addgroup"))) {
	    messages.add("You don't have permission to add groups");
	    model.addAttribute("messages", messages);
	    return groupsGet(request, response, model);
	}

	String oname = name;
	name = filtername(name);
	if (oname != null && !"".equals(oname) && !oname.equals(name)) {
	    messages.add("Name of new group should contain only digits, lowercase letters, period, _, and -");
	    return groupsGet(request, response, model);
	}	    
	if (name != null)
	    name = name.toLowerCase().trim();

	boolean sharing = "on".equals(sharingSt);
	boolean guests = "on".equals(guestSt);

	// if user isn't login manager, we didn't show them the options
	// these people can only create sharing groups
	if (!privs.contains("loginmanager")) {
	    sharing = true;
	    guests = false;
	}

	if (name != null && !sharing && !guests) {
	    messages.add("Sharing or guests (or both) must be specified for the new group");
	    return groupsGet(request, response, model);
	}

	boolean added = false;

	String user = (String)request.getSession().getAttribute("krb5user");

	String env[] = {"KRB5CCNAME=/tmp/krb5cc_" + user, "PATH=/bin:/user/bin"};

	if (del != null && del.size() > 0) {
	    for (String d: del) {
		// don't check for failure. We get a spruious failure because it tries to
		// delete a non-existent Kerberos policy entry
		logger.info("ipa group-del " + d);
		docommand.docommand(new String[]{"ipa", "group-del", d}, env);
	    }
	}

	if (name != null && !"".equals(name)) {
	    name = name.toLowerCase();
	    if (conf.reservedgroups != null) {
		String [] reserved = conf.reservedgroups.split(",");
		for (int i = 0; i < reserved.length; i++) {
		    if (name.matches(reserved[i].trim())) {
			messages.add(name + " is a reserved name");
			return groupsGet(request, response, model);
		    }
		}
	    }

	    SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
	    format.setTimeZone(TimeZone.getTimeZone("UTC"));
	    String dateString = format.format(new Date());

	    ArrayList<String> command = new ArrayList<String>();
	    command.add("ipa");
	    command.add("group-add");
	    if (!sharing)
		command.add("--nonposix");
	    if (guests)
		command.add("--setattr=businesscategory=login");
	    // dateOfCreate is most recent revalidation by the owner
	    // dateOfModify will be used for date owners were notified to revalidate
	    command.add("--setattr=dateOfCreate=" + dateString + "Z");
	    command.add(name);
	    logger.info(command);

	    var errors = new ArrayList<String>();
	    if (docommand.docommand(command.toArray(new String[1]), env, errors) == 0)
		added = true;
	    else
		messages.add("Unable to add group\n" + errors.toString());

	}

	if (added)
	    return groupController.groupGet(name, request, response, model);	
	else
	    return groupsGet(request, response, model);

    }

}
