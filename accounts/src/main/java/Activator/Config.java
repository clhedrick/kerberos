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
import java.io.*;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.StringTokenizer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.nio.file.Files;
import java.nio.file.attribute.FileTime;
import java.nio.file.Paths;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;

public class Config {
    public String ldapurl = null;
    public String ldapdn = null;
    public String ldappass = null;
    public String ldapbase = null;
    public String courseattribute = "rulinkrutgersedustudentcoursereg";
    public String dbdriver = null;
    public String dburl = null;
    public String dburl2 = null;
    public String dbuser = null;
    public String dbpass = null;
    public String csrolequery = null;
    public String csroleattr = null;
    public String uidtable =  null;
    public Map<String,String> log = new HashMap<String,String>();
    public String warningdir = "/var/lib/activator";
    public String warningtemplate = "/etc/activator.template";
    public int warningdays = 60;
    public String fromaddress = null;
    public String reservedgroups = null;
    public String testaddress = null;
    public String mailhost = null;
    public String defaultmaildomain = null;
    public String kerberosdomain = null;
    public String accountbase = null;
    public String base = null;
    public String kerbldapurl = null;
    public String groupmanagerfilter = null;
    public String groupsownedfilter = null;
    public String helpmail = null;
    public String usersuffix = null;
    public String usermgmturl = null;
    public String badpassfile = null;
    public String defaultgid = null;

    final static String CONFIGFILE = "/etc/activator.config";

    public class Rule {
	String filter;
	String groupName;
    }

    public class Cluster {
	public String name;
	List<Rule> rules;
	Set<String> groups;
	boolean docleanup;
	public boolean usermanaged;
	public String getName(){return name;}
    }
    
    public List<Cluster> clusters = new ArrayList<Cluster>();
    Cluster managed = null;
    Cluster departments = null;

    public String skipblank(String s) {
	for (int i = 0; i < s.length(); i++) {
	    if (s.charAt(i) != ' ')
		return s.substring(i);
	}
	return "";
    }

    public void loadConfig() throws FileNotFoundException, IOException,  FileNotFoundException{

	try (
	     BufferedReader br = new BufferedReader(new FileReader(CONFIGFILE));
	     ) {
		String line;
		Cluster cluster = null;
		String [] atoms = null;
		// parse global variables
		while ((line = br.readLine()) != null) {
		    // skip comment
		    if (line.startsWith("#"))
			continue;
		    atoms = line.split("[ \t]+", 2);
		    // skip blank line
		    if (line.trim().equals(""))
			continue;
		    // start of clusters
		    if (atoms[0].startsWith("[")) {
			break;
		    }
		    if (atoms.length < 2){
			throw new java.lang.IllegalArgumentException("unrecognized line " + line);
		    }
		    if (atoms[0].equals("ldapurl"))
			ldapurl = atoms[1];
		    if (atoms[0].equals("ldapdn"))
			ldapdn = atoms[1];
		    if (atoms[0].equals("ldappass"))
			ldappass = atoms[1];
		    if (atoms[0].equals("ldapbase"))
			ldapbase = atoms[1];
		    if (atoms[0].equals("courseattribute"))
			courseattribute = atoms[1];
		    if (atoms[0].equals("dbdriver"))
			dbdriver = atoms[1];
		    if (atoms[0].equals("dburl"))
			dburl = atoms[1];
		    if (atoms[0].equals("dburl2"))
			dburl2 = atoms[1];
		    if (atoms[0].equals("dbuser"))
			dbuser = atoms[1];
		    if (atoms[0].equals("dbpass"))
			dbpass = atoms[1];
		    if (atoms[0].equals("csrolequery"))
			csrolequery = atoms[1];
		    if (atoms[0].equals("csroleattr"))
			csroleattr = atoms[1];
		    if (atoms[0].equals("uidtable"))
			uidtable = atoms[1];
		    if (atoms[0].equals("warningdir"))
			warningdir = atoms[1];
		    if (atoms[0].equals("warningtemplate"))
			warningtemplate = atoms[1];
		    if (atoms[0].equals("warningdays")) {
			try {
			    warningdays = Integer.parseInt(atoms[1]);
			} catch (Exception e) {
			    // leave default value
			}
		    }
		    if (atoms[0].equals("fromaddress"))
			fromaddress = atoms[1];
		    if (atoms[0].equals("reservedgroups"))
			reservedgroups = atoms[1];
		    if (atoms[0].equals("testaddress"))
			testaddress = atoms[1];
		    if (atoms[0].equals("mailhost"))
			mailhost = atoms[1];
		    if (atoms[0].equals("defaultmaildomain"))
			defaultmaildomain = atoms[1];
		    if (atoms[0].equals("kerberosdomain"))
			kerberosdomain = atoms[1];
		    if (atoms[0].equals("accountbase"))
			accountbase = atoms[1];
		    if (atoms[0].equals("base"))
			base = atoms[1];
		    if (atoms[0].equals("kerbldapurl"))
			kerbldapurl = atoms[1];
		    if (atoms[0].equals("groupmanagerfilter"))
			groupmanagerfilter = atoms[1];
		    if (atoms[0].equals("groupsownedfilter"))
			groupsownedfilter = atoms[1];
		    if (atoms[0].equals("helpmail"))
			helpmail = atoms[1];
		    if (atoms[0].equals("usersuffix"))
			usersuffix = atoms[1];
		    if (atoms[0].equals("usermgmturl"))
			usermgmturl = atoms[1];
		    if (atoms[0].equals("badpassfile"))
			badpassfile = atoms[1];
		    if (atoms[0].equals("defaultgid"))
			defaultgid = atoms[1];

		}


		// clusters
		for (;line != null;line = br.readLine()) {
		    // skip comments
		    if (line.startsWith("#"))
			continue;
		    atoms = line.split("[ \t]+", 2);
		    // skip blank line
		    if (line.trim().equals(""))
			continue;
		    if (atoms.length < 1)
			continue;
		    // start of cluster
		    if (atoms[0].startsWith("[")) {
			if (!atoms[0].endsWith("]"))
			    throw new java.lang.IllegalArgumentException("section mark must end in ]");
			cluster = new Cluster();
			cluster.rules = new ArrayList<Rule>();
			cluster.groups = new HashSet<String>();
			cluster.name = atoms[0].substring(1, atoms[0].length()-1);
			cluster.docleanup = true;
			cluster.usermanaged = true;
			if ("managed".equals(cluster.name))
			    managed = cluster;
			else if ("departments".equals(cluster.name))
			    departments = cluster;
			else
			    clusters.add(cluster);
			continue;
		    }
		    // rules within cluster
		    if ("managed".equals(cluster.name) && atoms.length < 2)
			throw new java.lang.IllegalArgumentException("unrecognized line " + line);
		    
		    if (atoms[0].equals("-nocleanup"))
			cluster.docleanup = false;
		    if (atoms[0].equals("-nousermanaged"))
			cluster.usermanaged = false;
		    Rule rule = new Rule();
		    rule.groupName = atoms[0];
		    cluster.groups.add(atoms[0]);
		    if (atoms.length >= 2)
			rule.filter = atoms[1];
		    cluster.rules.add(rule);
		}
	    }

    }

    private static Config conf = null;
    private static long confTime = 0;

    public static Config getConfig() {
	if (conf == null) {
	    Config config = new Config();
	    try {
		config.loadConfig();
	    } catch (Exception e) {
		Logger logger = null;
		logger = LogManager.getLogger();
		logger.error("error loading config file " + e);
		throw new java.lang.IllegalArgumentException("unable to load configuration");
	    }
	    conf = config;
	    confTime = System.currentTimeMillis();
	    return conf;
	}
	if (System.currentTimeMillis() < (confTime + (120 * 1000))) {
	    return conf;
	}
	try {
	    long fileTime = Files.readAttributes(Paths.get(CONFIGFILE), BasicFileAttributes.class).creationTime().toMillis();
	    if (fileTime > confTime) {
		Config config = new Config();
		config.loadConfig();
		conf = config;
		confTime = fileTime;
	    }
	    return conf;
	} catch (Exception e) {
	    Logger logger = null;
	    logger = LogManager.getLogger();
	    logger.error("error loading config file " + e);
	    throw new java.lang.IllegalArgumentException("unable to load configuration");
	}
    }

}
	
	
