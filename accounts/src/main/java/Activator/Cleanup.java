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

public class Cleanup {

    static Set<String> managedGroups = new HashSet<String>();
    static List<String> managedPatterns = new ArrayList<String>();
    static Config config = null;
    static Logger logger = null;

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
		System.out.println("Can't find our hostname " + e);
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
	String logname = "log4j-trace.xml";
	if (verbose)
	    logname = "log4j-trace-verbose.xml";
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

	JndiAction action = new JndiAction(new String[]{"(businessCategory=login)", "", "host", "cn", "member", "owner", "creatorsName", "dateofcreate", "createTimestamp"});
	Subject.doAs(subj, action);
	if (action.data != null && action.data.size() > 0) {
	    grouploop:
	    for (Map<String,List<String>> group: action.data) {
		String name = lu.oneVal(group.get("cn"));
		if (managedGroups.contains(name))
		    continue;
		for (String pattern: managedPatterns) {
		    if (name.matches(pattern))
			continue grouploop;
		}
		logger.info("group " + name);
		if (lu.oneVal(group.get("dateofcreate")) != null)
		    logger.info("  created " + lu.oneVal(group.get("dateofcreate")));
		else
		    logger.info("  created " + lu.oneVal(group.get("createtimestamp")));

		Set<String>owners = Stream.concat(lu.valList(group.get("creatorsname")).stream(),
						  lu.valList(group.get("owner")).stream())
		    .filter(p -> p.startsWith("uid="))
		    .map(p -> lu.dn2user(p))
		    .filter(p -> p.matches("[0-9a-z]*"))
		    .collect(Collectors.toSet());

		logger.info("  owner " + owners);

		Set<String>members = lu.valList(group.get("member")).stream()
		    .filter(p -> p.startsWith("uid="))
		    .map(p -> lu.dn2user(p))
		    .collect(Collectors.toSet());

		logger.info("  members " + members);

	    }
	}

    }

}
