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
import java.util.Date;
import java.util.Set;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.TimeZone;
import java.util.Calendar;
import java.nio.file.Files;
import java.nio.file.Paths;
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
import Activator.User;
import Activator.Mail;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Controller
public class GroupController {

    @Autowired
    private LoginController loginController;

    @Autowired
    private GroupsController groupsController;

    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^-_.a-z0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    public String assureUser(List<String>messages, HttpServletRequest request, String name, boolean createOk) {
	Logger logger = null;
	logger = LogManager.getLogger();
	Config conf = Config.getConfig();

	try {
	    // if user isn't in our system, add them
	    Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	    if (subject == null) {
		messages.add("Session has expired");
		return "login";
	    }
	    String kname = (String)request.getSession().getAttribute("krb5user");
	    GSSCredential gssapi = (GSSCredential)request.getSession().getAttribute("gssapi");
	    
	    common.JndiAction action = new common.JndiAction(gssapi, new String[]{"(uid=" + name + ")", "", "uid"});
	    
	    Subject.doAs(subject, action);
	    if (action.val == null || action.val.size() == 0) {
		if (!createOk) {
		    messages.add(String.format("User %s isn't in our system.", name));
		    return "fail";
		}
		
		Activator.Ldap ldap = new Activator.Ldap();
		List<Map<String,List<String>>> universityDataList = ldap.lookup("(uid=" + name + ")", conf);
		Map<String,List<String>> universityData = null;
		
		// can't create an account without university data, but in cleanup I guess it could happen
		// so create empty data
		if (universityDataList == null || universityDataList.size() == 0) {
		    messages.add(String.format("%s: Can only add a netid that is in the University's data", name));
		    return "fail";
		}
		universityData = universityDataList.get(0);
		String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/user/bin"};
		if (!User.createUser(name, conf, universityData, false, logger, env))
		    return "fail";
		// notify users
		// replace %u with uid
		var message = "";
		try {
		    message = new String(Files.readAllBytes(Paths.get(conf.createtemplate)));
		} catch (Exception e) {
		    // no template, no message
		    messages.add(String.format("Please ask the user to go to %s and use the set password function.", conf.reviewurl));
		    return null;
		}
		message = message.replaceAll("%u", name);
		// first line is subject, so separate into subject and message
		var parts = message.split("\n", 2);
		// default address
		var toaddress = name + "@" + conf.defaultmaildomain;
		logger.info("Sending notification of account creation for " + name + " to " + toaddress);
		// for testing, can put a test address in conf file. It will
		// get all email rather than actual user
		if (!Mail.sendMail(conf.fromaddress, (conf.testaddress == null ? toaddress
						      : conf.testaddress), parts[0], parts[1])) {
		    messages.add("Attempt to send mail to " + toaddress + " failed. Please ask the user to go to " + conf.reviewurl + " and use the set password function.");
		    return null;
		}
	    }
	    return null;
	    
	} catch (Exception e) {
	    logger.error("Failure in assureUser " + e);
	    try {
		messages.add("Unexpected failure checking for User " + name);
	    } catch (Exception ignore) {}
	    return "fail";
	}
	
    }

    public String getUserDisplay(String userDn, Subject subject, GSSCredential gssapi, DirContext ctx, Config config) {
	Logger logger = null;
	logger = LogManager.getLogger();
	int i;
	String searchDn = userDn;

	common.JndiAction action = new common.JndiAction(gssapi, new String[]{"(objectclass=*)", userDn, "gecos"});
	// we're holding the context open, so use it
	action.noclose = true;
	action.ctx = ctx;
	Subject.doAs(subject, action);
	if (action.val.size() != 1) {
	    logger.error("failed to find " + userDn + " count " + action.val.size());
	    return lu.dn2user(userDn); // no gecos info, just return uid
	}
	Map<String, List<String>> attrs = action.data.get(0);
	if (attrs.get("gecos") != null) {
	    String gecos = attrs.get("gecos").get(0);
	    // gecos is name, other stuff, so drop anything after ,
	    i = gecos.indexOf(",");
	    if (i > 0)
		gecos = gecos.substring(0, i);
	    return lu.dn2user(userDn) + " (" + gecos + ")";
	}
	return lu.dn2user(userDn);
    }

    // class to export dn2user into thymeleaf
    public class Util {
	public String dn2user(String dn) {
	    return lu.dn2user(dn);
	}
    }

    @GetMapping("/groups/showgroup")
    public String groupGet(@RequestParam(value="name", required=false) String gname,
			   HttpServletRequest request, HttpServletResponse response, Model model) {

	// This module uses Kerberized LDAP. The credentials are part of a Subject, which is stored in the session.
	// This JndiAction junk is needed to execute the LDAP code in a context that's authenticated by
	// that Subject.

	// To separate logic from display, I've implemented my own API on top of the Sun LDAP code
	// It uses a class JndiAction that does an LDAP query and returns
	//   ArrayList<HashMap<String, ArrayList<String>>>
	// This is a list of things found by the query. For a lookup of a specific user or group the list will have just one member.
	// Each memory is a hashmap, with the key being attributes and the value a list of results.
	// E.g. map.get("uid") would get you the value of the uid attribute. Because some attributes can have more
	// than one value, the map returns a list of strings, not just one.
	//
	// lu.dn2user converts a dn to a username. If the dn starts with uid=XXXX, it returns XXXX. 
	//    otherwise it returns the whole dn

	GSSCredential gssapi = (GSSCredential)request.getSession().getAttribute("gssapi");

	gname = filtername(gname);

	Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	if (subject == null) {
	    List<String> messages = new ArrayList<String>();
	    messages.add("Session has expired");
	    model.addAttribute("messages", messages);
	    return loginController.loginGet("group", request, response, model); 
	}

	Config aconfig = new Config();
	try {
	    aconfig.loadConfig();
	} catch (Exception e) {
	    // We can't really do anything valid. Not sure going to showgroups will
	    // help, but it's the best I can think of.
	    List<String> messages = new ArrayList<String>();
	    messages.add("Unable to load configuration. Unable show show group information without it.");
	    model.addAttribute("messages", messages);
	    return groupsController.groupsGet(request, response, model); 
	}

	Map<String, List<String>> attrs = null;
	Map<String,String> memberNames = new HashMap<String,String>();
	boolean needsReview = false;

	Set<String>privs = (Set<String>)request.getSession().getAttribute("privs");
	boolean isLoginManager = privs.contains("loginmanager");

	// want to use the same context for a number of operations
	// try - finally to make sure it's always closed
	// the point is that we're going to make a bunch of ldap queries. 
	// we'd rather not make a separate authenticated connection to
	// the ldap server for each one. Instead use a single connection
	// for all the queries. The DirContext represents a connection.
	DirContext ctx = null;
	try {

	    // This acton isn't done until it's called by doAs
	    common.JndiAction action = new common.JndiAction(gssapi, new String[]{"(&(objectclass=groupofnames)(cn=" + gname + "))", "", "cn", "member", "host", "businessCategory", "dn", "gidNumber", "owner", "creatorsName", "dateofcreate", "createTimestamp"});
	    action.noclose = true; // hold context for reuse

	    // this is part of the Kerberos support. Subject is the internal data structure representing a Kerberos ticket.
	    // doas does an action authenticated as that subject. The action has to be a JndiAction. I supply a JndiAction does does
	    // an LDAP query, but you could do anything that uses GSSAPI authentication.
	    Subject.doAs(subject, action);
	    ctx = action.ctx; // get the context so we can use it for other operations
	    
	    if (action.val.size() != 1) {
		List<String> messages = new ArrayList<String>();
		messages.add("Group not found");
		model.addAttribute("messages", messages);
		return groupsController.groupsGet(request, response, model); 
	    }

	    attrs = action.data.get(0);

	    // we want to show the name of each user, so we have to look them up
	    // pass the front end a map from member dn to display
	    // actually just get all the people thta are going to be 
	    // displayed and build a single map for them all. No need
	    // for separate ones.
	    Set<String> people = new HashSet<String>();
	    List<String> members = attrs.get("member");
	    if (members != null) {
		// sort has nothing to do with building the map
		// but we'd like the output to be sorted
		// we're actually sorting dns, but since they
		// all start with uid= the sort should work OK
		Collections.sort(members);
		people.addAll(members);
	    }

	    List<String> owners = attrs.get("owner");
	    if (owners != null) {
	        Collections.sort(owners);
		people.addAll(owners);
	    }

	    List<String> creators = attrs.get("creatorsname");
	    if (creators != null) {
		for (String creator: creators) {
		    // creator can be a service. don't want that
		    if (creator.startsWith("uid="))
			people.add(creator);
		}
	    }

	    // now have all the people displayed on the page
	    // build a map from DN to what we want to display
	    for (String member: people) {
		String display = getUserDisplay(member, subject, gssapi, ctx, aconfig);
		// put it in the map
		memberNames.put(member, display);
	    }

	    // see if needs review. don't bother if no members
	    needsReview = utils.needsReview(attrs);

	} finally {
	    // we used noclose for all JndiActions, so we wouldn't get new connections for each user lookup
	    // so we have to close it explicitly
	    if (ctx != null)
		JndiAction.closeCtx(ctx);
	}

	// if we got an error from POST, we might already have messages.
	if (!model.containsAttribute("messages"))
	    model.addAttribute("messages", new ArrayList<String>());	    

	// set up model for display

	model.addAttribute("gname", gname);
	model.addAttribute("clusters", aconfig.clusters);
	model.addAttribute("group", attrs);
	model.addAttribute("membernames", memberNames);
	model.addAttribute("needsreview", needsReview);
	model.addAttribute("isloginmanager", isLoginManager);
	model.addAttribute("lu", new Util());

        return "groups/showgroup";
    }

    @PostMapping("/groups/showgroup")
    public String groupsSubmit(@RequestParam(value="groupname", required=false) String groupname,
			       @RequestParam(value="del", required=false) List<String>del,
			       @RequestParam(value="newmember", required=false) String newmember,
			       @RequestParam(value="delowner", required=false) List<String>delowner,
			       @RequestParam(value="newowner", required=false) String newowner,
			       @RequestParam(value="login", required=false) String loginSt,
			       @RequestParam(value="hosts", required=false) List<String>hosts,
			       @RequestParam(value="confirmmembers", required=false) String confirmMembers,
			       HttpServletRequest request, HttpServletResponse response,
			       Model model) {

	List<String>messages = new ArrayList<String>();
	model.addAttribute("messages", messages);
	((List<String>)model.asMap().get("messages")).clear();

	Logger logger = null;
	logger = LogManager.getLogger();

	String name = filtername(groupname);
	if (name == null || name.equals("") || !name.equals(groupname)) {
	    messages.add("Name of group should contain only digits, lowercase letters, period, _, and -");
	    return groupsController.groupsGet(request, response, model); 
	}

	Config conf = Config.getConfig();
	GSSCredential gssapi = (GSSCredential)request.getSession().getAttribute("gssapi");

	// Get current values of login attributes so we know what to change.
	// They show up as values of variables in action

	common.JndiAction action = new common.JndiAction(gssapi, new String[]{"(&(objectclass=groupofnames)(cn=" + name + "))", "", "member", "host", "businessCategory", "owner", "creatorsname"});

	Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	if (subject == null) {
	    messages.add("Session has expired");
	    return loginController.loginGet("group", request, response, model); 
	}

	Subject.doAs(subject, action);

	if (action.val == null || action.val.size() == 0) {
	    messages.add("Unable to find group");
	    return groupsController.groupsGet(request, response, model); 
	}

	Map<String, List<String>> attrs = action.data.get(0);

	boolean oldislogin = (attrs.get("businesscategory") != null && attrs.get("businesscategory").contains("login"));
	List<String> oldhosts = attrs.get("host");
	if (oldhosts == null)
	    oldhosts = new ArrayList<String>();
	List<String> oldmembers = new ArrayList<String>();
	if (attrs.get("member") != null) {
	    for (String m: attrs.get("member")) {
		oldmembers.add(lu.dn2user(m));
	    }
	}
	List<String> oldowners = new ArrayList<String>();
	if (attrs.get("owner") != null) {
	    for (String m: attrs.get("owner")) {
		oldowners.add(lu.dn2user(m));
	    }
	}
	List<String> creators = attrs.get("creatorsname");
	if (creators == null)
	    creators = new ArrayList<String>();
	List<String> creatorsNames = new ArrayList<String>();
	for (String m: creators) {
	    creatorsNames.add(lu.dn2user(m));
	}

	// if they aren't login manager, don't change login settings
	// ldap wouldn't let us do it, but don't want error messages
	Set<String>privs = (Set<String>)request.getSession().getAttribute("privs");
	boolean isLoginManager = privs.contains("loginmanager");

	boolean ok = true;

	String user = (String)request.getSession().getAttribute("krb5user");

	String env[] = {"KRB5CCNAME=/tmp/krb5cc_" + user, "PATH=/bin:/user/bin"};

	if (del != null && del.size() > 0) {
	    for (String d: del) {
		logger.info("ipa group-remove-member " + name + " --users=" + filtername(d));
		if (docommand.docommand (new String[]{"/bin/ipa", "group-remove-member", name, "--users=" + filtername(d)}, env) != 0) {
		    messages.add("Unable to remove user " + d + " from group");
		    continue;
		}
	    }
	    // other fields aren't populated, so return immediately
	    return groupGet(name, request, response, model);	
	}

	if (newmember != null) {
	    for (String a: newmember.split("\\s")) {
		a = a.trim();
		if (a != null && !a.equals("")) {
		    String retval;
		    if (oldmembers.contains(a)) {
			// non-fatal. continue with other operations
			messages.add("User " + a + " is already in the group.");
			continue;
		    } else if ((retval = assureUser(messages, request, filtername(a), oldislogin)) != null) {
			// error message already in model
			if (retval.equals("login"))
			    return loginController.loginGet("group", request, response, model); 
			else {
			    messages.add("Unable to create user " + filtername(a) + ".");
			    continue;
			}
		    } else {
			logger.info("ipa group-add-member " + name + " --users=" + filtername(a));
			if (docommand.docommand (new String[]{"/bin/ipa", "group-add-member", name, "--users=" + filtername(a)}, env) != 0) {
			    messages.add("Unable to add user " + filtername(a) + ".");
			    continue;
			}
		    }
		}
	    }
	}


	if (delowner != null && delowner.size() > 0) {

	    if (oldowners.size() < 2) {
		messages.add("Can't delete the last owner.");
		return groupGet(name, request, response, model);	
	    }

	    // for some reason this no longer works
	    if (false) {
		for (String d: delowner) {
		    logger.info("ip group-mod " + name + " --delattr=owner=uid=" + filtername(d) + conf.usersuffix);
		    if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=owner=uid=" + filtername(d) + conf.usersuffix}, env) != 0) {
			messages.add("Unable to delete user " + filtername(d) + " as owner.");
			continue;
		    }
		}
	    }

	    for (String d: delowner)
		oldowners.remove(filtername(d));

	    // oldowners is now updated to have all owners
	    var command = new ArrayList<String>();
	    command.add("/bin/ipa");
	    command.add("group-mod");
	    command.add(name);
	    for (var owner: oldowners)
		command.add("--owner=" + owner);
	    logger.info(command.toString());
	    if (docommand.docommand (command.toArray(new String[0]), env) != 0) {
		messages.add("Unable to update owners " + oldowners.toString());
	    }

	    // other fields aren't populated, so return immediately
	    return groupGet(name, request, response, model);	
	}


	if (newowner != null && newowner.trim().length() > 0) {
	    boolean first = true;
	    for (String n: newowner.split("\\s")) {
		n = n.trim();
		if (n != null && !n.equals("")) {
		    String retval;
		    if (oldowners.size() > 0 && oldowners.contains(n)) {
			messages.add("User " + n + " is already an owner.");
			continue;
		    } else if (oldowners.size() == 0 && creatorsNames.contains(n)) {
			messages.add("User " + n + " is already an owner.");
			continue;

		    } else if ((retval = assureUser(messages, request, filtername(n), false)) != null) {
			// error message already in model
			if (retval.equals("login"))
			    return loginController.loginGet("group", request, response, model); 
			else {
			    messages.add("Unable to create user " + filtername(n) + " for owner.");
			    continue;
			}
		    }
		    // if we've never modified the group, it will have a creator but no owners
		    // if we add an owner, we have to put the creator as the first owner. So if there's any
		    // owner we look at the owners and ignore the creator. Otherwise there's no way to
		    // delete the original creator from being an owner.
		    if (first && oldowners.size() == 0 && creators.size() > 0) {
			for (String c: creators) {
			    if (false) {
				logger.info("ipa group-mod " + name + " --addattr=owner=" + c);
				if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=owner=" + c}, env) != 0) { 
				    messages.add("Unable to add creator as owner: " + c);
				    return groupGet(name, request, response, model);
				}
			    }
			    oldowners.add(c);
			}
		    }
		    first = false;
		    if (false) {
			logger.info("ipa group-mod " + name + " --addattr=owner=uid=" + filtername(n) + conf.usersuffix);	     
			if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=owner=uid=" + filtername(n) + conf.usersuffix}, env) != 0) {
			    messages.add("Unable to add user " + n + " as owner.");
			    continue;
			}
		    }
		    oldowners.add(filtername(n));
		}
	    }

	    // oldowners is now updated to have all owners, new and old
	    // will give [a, b], need {a,b}. this isn't the most efficient but is the clearest
	    var command = new ArrayList<String>();
	    command.add("/bin/ipa");
	    command.add("group-mod");
	    command.add(name);
	    for (var owner: oldowners)
		command.add("--owner=" + owner);
	    logger.info(command.toString());
	    if (docommand.docommand (command.toArray(new String[0]), env) != 0) {
		messages.add("Unable to update owners " + oldowners.toString());
	    }

	}

	if (confirmMembers != null && confirmMembers.equals("true")) {
	    SimpleDateFormat format = new SimpleDateFormat("yyyyMMddHHmmss");
	    format.setTimeZone(TimeZone.getTimeZone("UTC"));
	    String dateString = format.format(new Date());

	    logger.info("ipa group-mod " + name + " --setattr=dateOfCreate=" + dateString + "Z");
	    if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--setattr=dateOfCreate=" + dateString + "Z"}, env) != 0) 
		messages.add("Unable to update information to show that group has been validated");

	    if (attrs.get("businesscategory") != null && attrs.get("businesscategory").contains("suspended")) {
		logger.info("ipa group-mod " + name + " --delattr=businesscategory=suspended");
		if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=businesscategory=suspended"}, env) != 0) 
		    messages.add("Unable to update information to show that group has been validated");
	    }

	    return groupGet(name, request, response, model);	
	}

	if (isLoginManager) {

	boolean login = "on".equals(loginSt);

	if (login && !oldislogin) {
	    logger.info("ipa group-mod " + name + " --addattr=businessCategory=login");
	    if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=businessCategory=login"}, env) != 0) {
		messages.add("Unable to set login for group");
	    }
	}
	/*
	  currently the field is disabled if on. That means no value shows for submit
	  since we don't allow it to be cleared, don't do this code

	  else if (!login && oldislogin) {
	    logger.info("ipa group-mod " + name + " --delattr=businessCategory=login");
	    if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=businessCategory=login"}, env) != 0) {
		messages.add("Unable to remove login for group");
	    }
	}
	*/

	ArrayList<String> clusters = new ArrayList<String>();

	Config aconfig = new Config();
	try {
	    aconfig.loadConfig();
	} catch (Exception e) {
	    messages.add("Unable to load configuration information");
	    // can't do anything below without this
	    return groupGet(name, request, response, model);
	}


	for (Config.Cluster cluster: aconfig.clusters)
	    clusters.add(cluster.name);

	if (hosts == null)
	    hosts = new ArrayList<String>();

	for (String cluster: clusters) {
	    if (hosts.contains(cluster) && !oldhosts.contains(cluster)) {
		logger.info("ipa group-mod " + name + " --addattr=host=" + cluster);
		if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=host=" + cluster}, env) != 0) {
		    messages.add("Unable to enable group for cluster " + cluster);
		}
	    } else if (!hosts.contains(cluster) && oldhosts.contains(cluster)) {
		logger.info("ipa group-mod " + name + " --delattr=host=" + cluster);
		if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=host=" + cluster}, env) != 0) {
		    messages.add("Unable to disable group for cluster " + cluster);
		}
	    }
	}

	} // isLoginManager

	return groupGet(name, request, response, model);	

    }

}

