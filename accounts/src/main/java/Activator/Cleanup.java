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

package Activator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.collections4.CollectionUtils;
import java.util.HashMap;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.StandardCopyOption;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.Arrays;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import java.net.InetAddress;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.sql.Blob;
import common.JndiAction;
import common.docommand;
import common.lu;
import common.utils;

public class Cleanup {

    static Set<String> managedGroups = new HashSet<String>();
    static List<String> managedPatterns = new ArrayList<String>();
    static Config config = null;
    static Logger logger = null;
    enum WarningType {
	NONE, FIRST, SECOND, CLOSE
    }

    static class KerberosConfiguration extends Configuration { 
        private String cc;
 
        public KerberosConfiguration(String cc) { 
            this.cc = cc;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useKeyTab", "true"); 
	    try {
		options.put("principal", config.servicesprincipal);
	    } catch (Exception e){
		logger.error("Can't find our hostname " + e);
	    }
            options.put("refreshKrb5Config", "true"); 
	    options.put("keyTab", "/etc/krb5.keytab.services");
 
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 

    static Subject getSubject() {
	Configuration kconfig = new KerberosConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, kconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext. " + le.getMessage());
	    System.exit(1);
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext. " + se.getMessage());
	    System.exit(1);
	}

	Subject subj = lc.getSubject();  
	if (subj == null) {
	    logger.error("Login failed");
	    System.exit(1);
	}

	return subj;
    }

    static void setupLog(boolean verbose) {
	String logname = "log4j-syslog.xml";
	if (verbose)
	    logname = "log4j-interactive.xml";
	System.setProperty("log4j.configurationFile", logname);

	logger = LogManager.getLogger();
    }

    static void loadManaged() {
	config = new Config();
	try {
	    config.loadConfig();
	} catch (Exception e) {
	    logger.error("error loading config file " + e);
	    System.exit(1);
	}
	managedGroups = config.managed.groups;
	for (Config.Rule rule: config.managed.rules) {
	    if ("course".equals(rule.groupName)) 
		managedPatterns.add(rule.filter);
	}

    }
	
    public static void main( String[] argarray) {

	ArrayList<String> args = new ArrayList<String>(Arrays.asList(argarray));

	boolean verbose = false;

	if (args.contains("-v")) {
	    verbose = true;
	    args.remove("-v");
	}
	    
	setupLog(verbose);
	loadManaged();
	
	Subject subj = getSubject();  

	JndiAction action = new JndiAction(null, new String[]{"(businessCategory=login)", "", "host", "cn", "member", "owner", "creatorsName", "dateofcreate", "createTimestamp", "businesscategory"});
	// JndiAction action = new JndiAction(null, new String[]{"(&(cn=clh2*)(businessCategory=login))", "", "host", "cn", "member", "owner", "creatorsName", "dateofcreate", "createTimestamp", "businesscategory"});
	Subject.doAs(subj, action);
	if (action.data != null && action.data.size() > 0) {
	    grouploop:
	    for (Map<String,List<String>> group: action.data) {

		// don't expire groups that are automatically managed
		String name = lu.oneVal(group.get("cn"));
		if (managedGroups.contains(name))
		    continue;
		for (String pattern: managedPatterns) {
		    if (name.matches(pattern))
			continue grouploop;
		}

		List<String>ownerDns = lu.valList(group.get("owner"));
		if (ownerDns.size() == 0) 
		    ownerDns = lu.valList(group.get("creatorsname"));

		Set<String>owners = ownerDns.stream()
		    .filter(p -> p.startsWith("uid="))
		    .map(p -> lu.dn2user(p))
		    .filter(p -> p.matches("[0-9a-z]*"))
		    .collect(Collectors.toSet());

		// forget it if we can't find an owner
		if (owners.size() == 0) {
		    logger.info("no usable owner " + name);
		    continue;
		}
			
		if (! lu.valList(group.get("businesscategory")).contains("login"))
		    continue;

		// group is the type that eventually needs review. Of course it may
		// not have reached that time yet.

		// file names: group:1 - first warning sent, group:2 - second warning sent
		//     group:close - closed; group:done - no longer needs review
		// config variables
		//    reviewdir: directory where the files are kept
		//    reviewtime: days after which review needs to be done, default no review
		//    review2ndwarning: days between first and second warning, default 15
		//    reviewclose: days between last warning and close, default 15
		//    reviewemail: email to notify when a close happens, no default
		//    reviewnoclose: true to not actually close but just mail reviewemail, default false

		var warnname = name;
		if (warnname.endsWith("-suspended"))
		    warnname = name.substring(0,name.length() - "-suspended".length());

		Path warningPath = Paths.get(config.reviewdir + "/" + warnname + ":1");
		Path warning2Path = Paths.get(config.reviewdir + "/" + warnname + ":2");
		Path warningClosePath = Paths.get(config.reviewdir + "/" + warnname + ":close");
		Path warningDonePath = Paths.get(config.reviewdir + "/" + warnname + ":done");

		Integer reviewTime = new Integer(config.reviewtime);
		Integer review2ndWarning = new Integer(config.review2ndwarning);
		Integer reviewCloseWarning = new Integer(config.reviewclose);

		boolean warned = Files.exists(warningPath);
		boolean warned2 = Files.exists(warning2Path);
		boolean warnedClose = Files.exists(warningClosePath);
		boolean warnedDone = Files.exists(warningDonePath);

		if (!utils.needsReview(group)) {
		    // hasn't expired.

		    // if it is suspended, unsuspend it
		    if (lu.valList(group.get("businesscategory")).contains("suspended")) {
			logger.info("ipa group-mod " + name + " --delattr=businesscategory=suspended");
			String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/usr/bin"};
			if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=businesscategory=suspended"}, env) != 0) {
			    logger.error("unable to remove businesscategory=suspended from " + name);
			    // faied; don't clear status if it's still suspended
			    continue;
			}
			if (name.endsWith("-suspended")) {
			    var newname = name.substring(0,name.length() - "-suspended".length());
			    logger.info("ipa group-mod " + name + " --rename " + newname);
			    if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--rename", newname}, env) != 0) {
				logger.error("unable to rename " + name + " to " +newname);
				continue;
			    }
			    // this is a bad combination. suspended has been removed but hasn't bee renamed
			}

			    
		    }

		    //  If we warned them, rename the warning to done
		    try {
			if (warned)
			    Files.move(warningPath, warningDonePath, StandardCopyOption.REPLACE_EXISTING);
			if (warned2)
			    Files.move(warning2Path, warningDonePath, StandardCopyOption.REPLACE_EXISTING);
			if (warnedClose)
			    Files.move(warningClosePath, warningDonePath, StandardCopyOption.REPLACE_EXISTING);
			if (warned || warned2 || warnedClose)
			    logger.info("Cleanup: group " + name + " has been confirmed");
		    } catch (Exception e) {
			logger.error("unable to rename state file to done " + e);
		    }

		    // and don't do anything
		    continue;
		}

		// if here, the group needs review

		Set<String>members = lu.valList(group.get("member")).stream()
		    .filter(p -> p.startsWith("uid="))
		    .map(p -> lu.dn2user(p))
		    .collect(Collectors.toSet());

		// any done is out of date; remove it
		if (warnedDone) {
		    try {
			Files.delete(warningDonePath);
		    } catch (Exception e) {
			logger.error("Can't delete " + warningDonePath + " " + e);
		    }
		}

		// put text of message here
		StringBuilder text = new StringBuilder();

		Instant now = Instant.now();
		Instant warnedDate = null;
		Instant warned2Date = null;

		if (warned) {
		    try {
			warnedDate = Files.getLastModifiedTime(warningPath).toInstant();
		    } catch (Exception e) {
			logger.error("Can't get date for " + warningPath + " " + e);
			continue;
		    }
		}

		if (warned2) {
		    try {
			warned2Date = Files.getLastModifiedTime(warning2Path).toInstant();
		    } catch (Exception e) {
			logger.error("Can't get date for " + warning2Path + " " + e);
			continue;
		    }
		}

		WarningType warningType = WarningType.NONE;

		// first warning if not warned at all
		if (! warned && ! warned2 && ! warnedClose) {
		    warningType = WarningType.FIRST;

		} else if (warned && ! warned2 && ! warnedClose &&
			   warnedDate.plus(review2ndWarning, ChronoUnit.DAYS)
			      .compareTo(now) < 0) {
		    warningType = WarningType.SECOND;
		    
		} else if (warned2 && ! warnedClose && 
			   warned2Date.plus(reviewCloseWarning, ChronoUnit.DAYS)
			      .compareTo(now) < 0) {
		    warningType = WarningType.CLOSE;

		} else 
		    // not time for any warning
		    continue;

		String subject;

		// first warning
		if (warningType == WarningType.FIRST)
		    subject = "Review needed for user group " + name + " to maintain access to system";
		else if (warningType == WarningType.SECOND) 
		    subject = "2nd warning: Review needed for user group " + name + " to maintain access to system";
		else
		    subject = "User group " + name + " being suspended";

		text.append("\n");
		text.append("You are the owner of user group: " + name + "\n");
		text.append("\n");
		text.append("Users in this group are allowed to use the following clusters. This\n");
		text.append("group may also be used to control access to systems that you\n");
		text.append("manage. Those systems won't be in this list.\n");
		text.append("\n");
		for (String s: lu.valList(group.get("host"))) {
		    text.append("   " + s + "\n");
		}
		text.append("\n");
		text.append("Because this group is used to authorize users to login, it needs to be\n");
		text.append("reviewed every " + reviewTime + " days.\n");
		text.append("\n");
		text.append("Here are the current users:\n");
		text.append("\n");
		for (String m: members) {
		    text.append("   " + m + "\n");
		}
		text.append("\n");

		if (warningType == WarningType.CLOSE) {
		    text.append("Because you have not responded to the previous warnings, this group\n");
		    text.append("is being suspended.\n");
		    text.append("\n");
		}
		text.append("Please go to the account management application at\n");
		text.append("   " + config.reviewurl + "\n");
		text.append("\n");
		text.append("* Choose \"Group and Guest Management.\"\n");
		text.append("* Once you have logged in, you will see a list of all the groups you\n");
		text.append("  control. Some of them will be marked \"Needs review.\" \n");
		text.append("  For each group that needs review, click on the group.\n");
		text.append("* Review the users currently in the group, removing any than no longer\n");
		text.append("  need access to these systems, using the red X icon\n");
		text.append("* Once the group membership is correct, click on the button labelled\n");
		text.append("  \"Confirm Membership.\"\n");
		text.append("* If you no longer have any users you need to authorize, you may remove the\n");
		text.append("  group entirely, using the red X in the main list of groups.\n");
		text.append("\n");
		text.append("When you remove users from the group, they may no longer be authorized to\n");
		text.append("login. If so, we will warn them via email, giving them " + config.warningdays + " days to\n");
		text.append("move any information that they are going to need.\n");

		// if there are multiple owners, only do this once, so don't put it
		// in the loop over owner.
		if (warningType == WarningType.CLOSE) {
		    // shouldn't be possible that it's already suspended, but if so, nothing to do
		    if (! lu.valList(group.get("businesscategory")).contains("suspended")) {
			// user hasn't responded, make group not login and rename it
			// maintain its member and GID, so it can still be used for file sharing
			String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/usr/bin"};
			logger.info("ipa group-mod " + name + " --addattr=businesscategory=suspended");
			if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=businesscategory=suspended"}, env) != 0) {
			    logger.error("unable to add businesscategory=suspended to " + name);
			    continue;   // don't notify if it fails
			}

			// should be impossible, but don't create -suspended-suspended
			if (! name.endsWith("-suspended")) {
			    logger.info("ipa group-mod " + name + " --rename " + name + "-suspended");
			    if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--rename", name + "-suspended"}, env) != 0) {
				logger.error("unable to rename group to " + name + "-suspended");
				continue;   // don't notify if it fails
			    }
			}

		    }
		}

		// if there is more than one owner, only change files around the first time
		boolean changedone = false;
		for (String owner: owners) {
		    String toaddress = owner + "@" + config.defaultmaildomain;

		    // for testing, can put a test address in config file. It will
		    // get all email rather than actual user
		    if (Mail.sendMail(config.fromaddress, config.replytoaddress, 
				      (config.testaddress == null ? toaddress : config.testaddress), 
				      (config.testaddress == null ? "" : (toaddress + ": ")) + 
				          subject, 
				      text.toString())) {
			try {
			    if (warningType == WarningType.FIRST) {
				logger.info("Cleanup: first warning " + name + " " + toaddress + " " + members + " " + lu.valList(group.get("host")));
				if (!changedone) 
				    Files.write(warningPath, new byte[]{});
			    } else if (warningType == WarningType.SECOND) {
				logger.info("Cleanup: second warning " + name + " " + toaddress + " " + members + " " + lu.valList(group.get("host")));
				if (!changedone) {
				    Files.delete(warningPath);
				    Files.write(warning2Path, new byte[]{});
				}
			    } else {
				logger.info("Cleanup: close " + name + " " + toaddress + " " + members + " " + lu.valList(group.get("host")));
				if (!changedone) {
				    Files.delete(warning2Path);
				    Files.write(warningClosePath, new byte[]{});
				}
			    }
			} catch (Exception e) {
			    logger.error("Can't update files " + e);
			}
			changedone = true;
		    }
		}
	    }
	}

    }

}
