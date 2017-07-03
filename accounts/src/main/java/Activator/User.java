package Activator;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
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
	 
/*

   This program is driven by LDAP data.  I've written a small middleware on top of the usual Ldap API.
   It turns the output into something like the PHP data: a list of entries. Each entry is a map from attributes
   to values. E.g. if we looked for users we might get

      [{"hedrick", {"cn": ["Charles Hedrick"], "type": ["faculty", "staff"]}},
       {"smith", {"cn": ["John Smith"], "type": ["student", "student worker"]}}]

   The other major data structure is Config. It has sections. A key section is headed with
   [managed] That's where the automatically managed groups are defined. A lot of code here
   gets that section and then either checks whether groups are automatically maintained
   or runs the rules to get all the user's automatic group memberships based on LDAP data.

   It has regexp's defining which groups are course groups. We want to make sure that
   cs509f16 is a course group but cs509f16-admin is not. cs509f16-admin would me a manually
   maintained group. We have to know which is which because we'll remove members from
   cs509f16 if LDAP doesn't generate any, but we won't touch the membership of cs509f16-admin.

   Match.makeclass turns an LDAP DN like 2016:9:16:198:510:01 into cs510-f16.  Currently if 
   it's not NB computer science it generates dept1234-510-f16. To support other departments
   by name you'd have to modify the code in Match and also the regexps. But you'd have to
   check whether there are any existing manually created groups that overlap the new names.

 */

public class User {

    String warningtemplate = null;

    // This is to avoid having to put the configuraiton in a file.
    // The contents of the file would be host-specific. I'd rather generate it dynamically.

   class KerberosConfiguration extends Configuration { 
        private String cc;
 
        public KerberosConfiguration(String cc) { 
            this.cc = cc;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useKeyTab", "true"); 
	    try {
		options.put("principal", "host/" + InetAddress.getLocalHost().getCanonicalHostName() + "@" + Config.getConfig().kerberosdomain); 
	    } catch (Exception e){
		System.out.println("Can't find our hostname " + e);
	    }
            options.put("refreshKrb5Config", "true"); 
	    options.put("keyTab", "/etc/krb5.keytab");
 
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 

    public KerberosConfiguration makeKerberosConfiguration(String cc) {
	return new KerberosConfiguration(cc);
    }

    // based on results of ldap query to Rutgers ldap, get the list of groups they are in
    // that we manage. based on [managed] section of config file
    public Set<String> makeUserMaintainedGroups(Config config, Map<String,List<String>> universityData) {
	Set<String>retGroups = new HashSet<String>();

	// non-course groups. these are defined by ldap filters, so we run the filters on each group
	for (Config.Rule rule: config.managed.rules) {
	    if (!"course".equals(rule.groupName) && Match.matchLdap(universityData, rule.filter)) {
		retGroups.add(rule.groupName);
	    }
	}

	// add the groups for courses we manage
	// have to check the courses the user is in one by one, and then apply the regexp's
	List<String>courses = universityData.get(config.courseattribute);
	if (courses != null)
	    // for each course the user is in, run the course rules. Last match wins
	    for (String course: courses) {
		// the rules are on group name, not course id, so make group name
		// convert from 2016:9:16:198:510:01 to cs510-f16
		String courseGroup = Match.makeclass(course, config);
		boolean ok = false;
		for (Config.Rule rule: config.managed.rules) {
		    // only use the rules that are for courses, obviously
		    if ("course".equals(rule.groupName)) {
			// see if it's an exception rule
			if (rule.filter.charAt(0) == '!') {
			    if (courseGroup.matches(rule.filter.substring(1))) {
				ok = false;
			    }
			} else {
			    if (courseGroup.matches(rule.filter)) {
				ok = true;
			    }
			}
		    }
		}
		if (ok)
		    retGroups.add(courseGroup);
	    }

	return retGroups;
    }
			
    // check config file to see if this course gets accounts on this cluster
    private static boolean isCourseOkForCluster(String group, Config.Cluster cluster) {
	boolean ok = false;
	for (Config.Rule rule: cluster.rules) {
	    if ("course".equals(rule.groupName)) {
		if (rule.filter.charAt(0) == '!') {
		    if (group.matches(rule.filter.substring(1)))
			ok = false;
		} else {
		    if (group.matches(rule.filter))
			ok = true;
		}
	    }
	}
	return ok;
    }

    // a course group is one that matches the course filters in the
    // [managed] section
    private boolean isCourseGroup(String group, Config config) {
	return isCourseOkForCluster(group, config.managed);
    }

    private Map<String, Set<String>> loginClusterCache = new HashMap<String, Set<String>>();

    // See what clusters this group is allowed on. 
    // Only for manually maintained groups
    // cache the data, because when we're reviewing accounts this could be done a lot
    public Set<String> getLoginClustersDn(String dn, Subject subj, Config config) {
	String groupName = dn2group(dn);

	// if it's an illegal dn
	if (groupName == null) {
	    return null;
	}

	// can't just get it and check for null because null is a valid value
	if (loginClusterCache.containsKey(groupName))
	    return loginClusterCache.get(groupName);

	// this is for manually maintained groups, so exclose automatch groups
	// there are two types of automatic group: course and other, with somewhat different tests
	if (isCourseGroup(groupName, config) || config.managed.groups.contains(groupName)) {
	    loginClusterCache.put(groupName, null);
	    return null;
	}

	int i = dn.indexOf("," + config.accountbase);

	if (i < 0) {
	    throw new java.lang.IllegalArgumentException("invalid dn " + dn);
	}
	String relDn = dn.substring(0, i);

	// ldapsearch with the group dn as base and a test for whether it's login
	JndiAction action = new JndiAction(new String[]{"(businessCategory=login)", relDn, "host", "cn"});
	Subject.doAs(subj, action);
	if (action.val != null && action.val.size() > 0) {
	    // normal group, return set of clusters it's valid for
	    // make a set out of the values of the host attribute
	    Set<String> clusters = new HashSet<String>(action.val.get(0).get("host"));
	    loginClusterCache.put(groupName, clusters);
	    return clusters;
	}
	// couldn't find group. presumably because it's not a login group
	loginClusterCache.put(groupName, null);
	return null;
    }

    // See what clusters this group is allowed on. 
    // Only for manually maintained groups
    // cache the data, because when we're reviewing accounts this could be done a lot
    // This is roughly the same as getLoginClustersDn. It just takes the name rather than the DN.
    public Set<String> getLoginClusters(String groupName, Subject subj, Config config) {
	// can't just get it and check for null because null is a valid value
	if (loginClusterCache.containsKey(groupName))
	    return loginClusterCache.get(groupName);

	// if it's a course group or a group we maintain automatically, return null
	if (isCourseGroup(groupName, config) || config.managed.groups.contains(groupName)) {
	    loginClusterCache.put(groupName, null);
	    return null;
	}

	// ldapsearch with the group dn as base and a test for whether it's login
	JndiAction action = new JndiAction(new String[]{"(&(cn=" + groupName + ")(businessCategory=login))", "", "host", "cn"});
	Subject.doAs(subj, action);
	if (action.val != null && action.val.size() > 0) {
	    // normal group, return set of clusters it's valid for
	    // make a set out of the values of the host attribute
	    Set<String> clusters = new HashSet<String>(action.val.get(0).get("host"));
	    loginClusterCache.put(groupName, clusters);
	    return clusters;
	}
	// couldn't find group. presumably because it's not a login group
	loginClusterCache.put(groupName, null);
	return null;
    }

    // Does group exist. Used for automatic groups, so won't be in the cache
    public boolean groupExists(String groupName, Subject subj, Config config) {

	// ldapsearch with the group dn as base and a test for whether it's login
	JndiAction action = new JndiAction(new String[]{"(cn=" + groupName + ")", "", "cn"});
	Subject.doAs(subj, action);
	if (action.val != null && action.val.size() > 0) {
	    return true;
	}
	return false;
    }


    public static String dn2group(String s) {
	int i = s.indexOf(",");
	if (s.startsWith("cn="))
	    return s.substring(3, i);
	return null;
    }

    // the real intent here is to return user's membership in manually maintained groups
    // either for one cluster or all clusters if cluster is null
    public List<String> makeManualLoginGroups(Config config, ArrayList<HashMap<String,ArrayList<String>>>val, Subject subj, String cluster) {
	List<String>loginGroups = new ArrayList<String>();

	// ourData is data from our ldap server. may be missing if it's a new user. use empty list for that
	HashMap<String, ArrayList<String>> ourData = null;
	if (val == null || val.size() == 0)
	    ourData = new HashMap<String, ArrayList<String>>();
	else
	    ourData = val.get(0);

	// now look at the groups the user is in, and pick out those that are login groups
	// but not course groups or managed groups (since we only want manually maintained groups)
	// This is a list of DNs, not group names.
	ArrayList<String>groupDns = ourData.get("memberof");
	if (groupDns == null)
	    groupDns = new ArrayList<String>();
	// this is dns, not names, but that's what we need to do queries
	for (String dn: groupDns) {
	    // grtLoginClusters returns clusters this group is a login group for
	    // null if it's not a login group
	    Set<String>clusters = getLoginClustersDn(dn, subj, config);
	    String name = dn2group(dn);
	    // invalid group dn
	    if (name == null)
		continue;
	    // not a login group
	    if (clusters == null)
		continue;
	    if (cluster == null) {
		// asked for all groups regardless of cluster
		loginGroups.add(name);
	    } else if (clusters.contains(cluster)) {
		// asked for specific cluster
		loginGroups.add(name);
	    }
	}
	return loginGroups;
    }

    // set of groups that are automatically maintained that the user is currently in. Based on CS LDAP.
    public Set<String> makeExistingAutomaticGroups(Config config, ArrayList<HashMap<String,ArrayList<String>>>val) {
	Set<String>loginGroups = new HashSet<String>();

	// ourData is data from our ldap server. may be missing if it's a new user. use empty list for that
	HashMap<String, ArrayList<String>> ourData = null;
	if (val == null || val.size() == 0)
	    ourData = new HashMap<String, ArrayList<String>>();
	else
	    ourData = val.get(0);

	// now look at the groups the user is in, and pick out those that are not automatically maintained, i.e.
	// not course groups or managed groups
	ArrayList<String>groupDns = ourData.get("memberof");
	if (groupDns == null)
	    groupDns = new ArrayList<String>();
	// this is dns, not names, but that's what we need to do queries
	for (String dn: groupDns) {
	    // get name of group
	    String name = dn2group(dn);
	    // invalid group dn
	    if (name == null)
		continue;
	    if (isCourseGroup(name, config) || config.managed.groups.contains(name)) {
		loginGroups.add(name);
	    }
	}
	return loginGroups;
    }

    public boolean isCurrentlyInGroup(Config config, ArrayList<HashMap<String,ArrayList<String>>>val, String group) {
	if (val == null || val.size() == 0)
	    return false;

	String match = "cn=" + group + ",";

	ArrayList<String>groupDns = val.get(0).get("memberof");
	if (groupDns == null)
	    return false;

	// this is dns, not names, so have to match with cn=NNN,...
	for (String dn: groupDns) {
	    // get name of group
	    if (dn.startsWith(match))
		return true;
	}

	return false;
    }

    public static boolean createUser(String username, Config config, Map<String,List<String>> universityData, boolean test, Logger logger, String[] env) {
	long uid = Uid.allocateUid(username, config);
	List<String> firstl = universityData.get("givenname");
	String first;
	if (firstl == null)
	    first = "-";
	else 
	    first = firstl.get(0);
	List<String> lastl = universityData.get("sn");
	String last;
	if (lastl == null)
	    last = "-";
	else 
	    last = lastl.get(0);
	List<String> gecosl = universityData.get("cn");
	String gecos;
	if (gecosl == null)
	    gecos = "-";
	else
	    gecos = gecosl.get(0);
	
	logger.info("ipa user-add " + username + " --uid=" + uid + " --first=" + first + " --last=" + last + " --gecos=" + gecos + " --random");
	if (!test) {
	    if (docommand.docommand (new String[]{"/bin/ipa", "user-add", username, "--uid=" + uid, "--first=" + first, "--last=" + last, "--gecos=" + gecos, "--random"}, env) != 0)
		return false;
	}
	return true;
    }

    // user exists in both sets of update. Update our info if it's different
    // don't bother returning a value because we'll continue with other stuff even if this fails
    static void syncUser(String username, Config config, Map<String,List<String>> universityData, HashMap<String,ArrayList<String>> ourData, boolean test, Logger logger, String[] env) {
	List<String> mods = new ArrayList<String>();

	boolean needmod = false;
	String first = lu.oneVal(universityData.get("givenname"),"-");
	String ofirst = lu.oneVal(ourData.get("givenname"));
	if (!first.equals(ofirst)) {
	    needmod = true;
	}

	String last = lu.oneVal(universityData.get("sn"),"-");
	String olast = lu.oneVal(ourData.get("sn"));
	if (!last.equals(olast)) {
	    needmod = true;
	}

	String cn = lu.oneVal(universityData.get("cn"),"-");
	String ocn = lu.oneVal(ourData.get("gecos"));
	if (!cn.equals(ocn)) {
	    needmod = true;
	}

	if (needmod) {
	    logger.info("ipa user-mod " + username + " --first=" + first + " --last=" + last + " --gecos=" + cn);
	    if (!test) {
		// continue even if this fails
		docommand.docommand (new String[]{"/bin/ipa", "user-mod", username, "--first=" + first, "--last=" + last, "--gecos=" + cn}, env);
	    }
	}
    }

    public static void main( String[] argarray) {

	ArrayList<String> args = new ArrayList<String>(Arrays.asList(argarray));

	boolean verbose = false;
	boolean cleanup = false;
	boolean test = false;

	if (args.contains("-v")) {
	    verbose = true;
	    args.remove("-v");
	}
	    
	if (args.contains("-c")) {
	    cleanup = true;
	    args.remove("-c");
	}
	    
	if (args.contains("-t")) {
	    test = true;
	    args.remove("-t");
	}

	if (!cleanup && args.size() < 1) {
	    System.out.println("");
	    System.out.println("test USER - show what systems will be in the main activator menu");
	    System.out.println("test USER CLUSTER - activate user for that cluster");
	    System.out.println("test -c [USER] - do cleanup, one user if specified else everyone");
	    System.out.println("   -t for test - show what would happen but don't do it");
	    System.out.println("   -v for verbose - show data about user so you can follow the program logic");
	    System.out.println("");
	    System.out.println("Actions actually done  are logged to syslog, actions and debug info to stdout");
	    System.out.println("");
	    System.exit(1);
	}
	String username = null;
	if (args.size() > 0)
	    username = args.get(0);
	List<String> clusters = null;
	List<String> currentClusters = null;
	List<String> ineligibleClusters = null;

	// variables for actual activator
	String requestedCluster = null;
	if (cleanup) {
	    requestedCluster = null;
	    clusters = null;
	} else if (args.size() > 1) {
	    requestedCluster = args.get(1);
	    clusters = null;
	} else {
	    requestedCluster = null;
	    clusters = new ArrayList<String>();	    
	    currentClusters = new ArrayList<String>();	    
	    ineligibleClusters = new ArrayList<String>();
	}
	    
	// The actual ipa commands are info; other stuff debug

	// For test the ipa commands don't happen, so
	// log to console only; syslog only shows actual actions

	// For verbose debug level to console, info to syslog (if not test)

	// log info to console and syslog
	String logname = "log4j-interactive.xml";
	// log debug to console
	if (verbose && test)
	    logname = "log4j-trace-verbose.xml";
	// log debug to console and info to syslog
	else if (verbose)
	    logname = "log4j-verbose.xml";
	// log info to console
	else if (test)
	    logname = "log4j-trace.xml";

	// in the web context, the configuration file comes
	// from WEB-INF. It's the first file that matches
	// log4j2*xml
	System.setProperty("log4j.configurationFile", logname);

	if (doUser(username, clusters, currentClusters, ineligibleClusters, requestedCluster, cleanup, test, false))
	    System.out.println("success");
	else
	    System.out.println("failed");

	if (clusters != null) {
	    System.out.println("currently on " + currentClusters);
	    System.out.println("can activate on " + clusters);
	    System.out.println("will be removed from " + ineligibleClusters);
	}
    }

    // must specify one of the following
    //   activatableClusters, currentClusters, ineligibleClusters, supplied as empty lists that doUser will fill in
    //       this is the main screen of the web app
    //   requested cluster - activation for that cluster - the activation screen of the web app
    //   cleanup - batch account cleanup
    //   isweb - is it called from web or command line. currently not used
    public static boolean doUser (String username, List<String>activatableClusters, List<String>currentClusters, List<String>ineligibleClusters, String requestedCluster, boolean cleanup, boolean test, boolean isWeb) {

	Logger logger = null;
	logger = LogManager.getLogger();

	User user = new User();

	Config config = new Config();
	try {
	    config.loadConfig();
	} catch (Exception e) {
	    logger.error("error loading config file " + e);
	    return false;
	}

	Ldap ldap = new Ldap();

	// begin boilerplate for talking to the LCSR ldap server
	// need credentials for our host to authenticate the LDAP query

	Configuration kconfig = user.makeKerberosConfiguration(null);
	LoginContext lc = null;
	try {
	    lc = new LoginContext("Groups", null, null, kconfig);
	    lc.login();
	} catch (LoginException le) {
	    logger.error("Cannot create LoginContext. " + le.getMessage());
	    return false;
	} catch (SecurityException se) {
	    logger.error("Cannot create LoginContext. " + se.getMessage());
	    return false;
	}

	Subject subj = lc.getSubject();  
	if (subj == null) {
	    logger.error("Login failed");
	    return false;
	}

	Db db = new Db();
	if (config.csroleattr != null)
	    db.openDb(config);

	// end boilerplate

	// try over all users
	try {
	    ArrayList<HashMap<String,ArrayList<String>>> users;

	    // for real cleanup check all currently active users
	    //   otherwise just specified user
	    if (cleanup && username == null) {
		JndiAction action = new JndiAction(new String[]{"(&(objectclass=inetorgperson)(memberof=cn=login-*,*))", "", "uid"});
		Subject.doAs(subj, action);

		users = action.val;
		System.out.println("users " + users.size());
	    } else {
		users = new ArrayList<HashMap<String,ArrayList<String>>>();
		HashMap<String,ArrayList<String>> userMap = new HashMap<String,ArrayList<String>>();
		ArrayList<String> uidList = new ArrayList<String>();
		uidList.add(username);
		userMap.put("uid", uidList);
		users.add(userMap);
	    }

	    for (HashMap<String,ArrayList<String>> userMap: users) {
		ArrayList<String> usernames = userMap.get("uid");
		if (usernames == null || usernames.size() == 0)
		    continue;
		username = usernames.get(0);

		List<String> addtoCluster = new ArrayList<String>();
		List<String> removefromCluster = new ArrayList<String>();

		if (activatableClusters != null)
		    logger.debug("Requesting clusters user " + username);		    
		else if (cleanup)
		    logger.debug("Doing cleanup for user " + username);
		else
		    logger.debug("Running as activator for user " + username + " for cluster " + requestedCluster);

		// all operations for individual user is in a try, so we can continue
		//  with other users after an error
		try {

		    // get data from University for this user

		    List<Map<String,List<String>>> universityDataList = ldap.lookup("(uid=" + username + ")", config);
		    Map<String,List<String>> universityData = null;

		    // can't create an account without university data, but in cleanup need to deal
		    // with user that are no longer there, so create empty data
		    if (universityDataList != null && universityDataList.size() > 0)
			// can only have one entry with a given uid
			universityData = universityDataList.get(0);
		    else {
			universityData = new HashMap<String,List<String>>();
		    }

		    // now add in data from CS database. It becomes an attribute in the LDAP
		    // data structure, so filters can check it along with University data
		    List<String>csroles = db.getRoles(username, config);
		    if (config.csroleattr != null)
			universityData.put(config.csroleattr, csroles);

		    // get group memberships from our data; result is action.val
		    // will be filtered below to find manually maintained groups this user is in for a specific cluster
		    JndiAction action = new JndiAction(new String[]{"(uid=" + username + ")", "", "memberOf", "givenname", "sn", "gecos"});
		    Subject.doAs(subj, action);

		    if ((action.val == null || action.val.size() == 0) &&
			(universityData.get("uid") == null || universityData.get("uid").size() == 0)) {
			logger.debug("user " + username + " doesn't exist in University data or our system. Skipping.");
			if (cleanup)
			    continue;
			else
			    return false;
		    }
	
		    // get automaticallly maintained groups from University data. will have to filters to see if they fit the cluster
		    Set<String> userMaintainedGroups = user.makeUserMaintainedGroups(config, universityData);
		    // list of login groups for all clusters - just for logging
		    Set<String> userManualLoginGroups = new HashSet<String>();
		    // list clusters user is allowed on
		    Set<String> userAllowedClusters = new HashSet<String>();

		    // print the clusters they can login on.
		    for (Config.Cluster cluster: config.clusters) {
			logger.debug("For cluster " + cluster.name);
			// for each group user is in from univ data (usermainainedgroups)
			//   if course
			//      filter with cluster's course list
			//   no,
			//      filter with cluster's group list
			boolean ok = false;
			logger.debug("  Automatic groups:");
			for (String group: userMaintainedGroups) {
			    if (user.isCourseGroup(group, config)) {
				if (user.isCourseOkForCluster(group, cluster)) {
				    ok = true;
				    logger.debug("    " + group);
				}
			    } else {
				if (cluster.groups.contains(group)) {
				    ok = true;
				    logger.debug("    " + group);
				}
			    }
			}
			// for each manually maintained group user is from our data
			// we get only manually maintained login groups for this user for this cluster
			logger.debug("  Manual groups:");
			List<String> manualLoginForCluster = user.makeManualLoginGroups(config, action.val, subj, cluster.name);
			// merge into full list for log info
			userManualLoginGroups.addAll(manualLoginForCluster);
			
			for (String group: manualLoginForCluster) {
			    logger.debug("    " + group);
			    ok = true;
			}			

			boolean current = user.isCurrentlyInGroup(config, action.val, "login-" + cluster.name);

			logger.debug("  User should be able to login for " + cluster.name + ": " + ok);
			if (ok && ! current) {
			    logger.debug("  Need to set login for " + cluster.name);
			    addtoCluster.add(cluster.name);
			}
			if (!ok && current) {
			    logger.debug("  Need to clear login for " + cluster.name);
			    removefromCluster.add(cluster.name);
			}
			// caller wants to know allowed clusters. 
			// classify into the appropriate 3 groups
			// activatableClusters is a list to be returned for the "list" function
			// so if it's set this is a list function
			if (activatableClusters != null) {
			    if (current && ok)
				currentClusters.add(cluster.name);
			    else if (current)  // in it but shouldn't be; will get cleaned up
				ineligibleClusters.add(cluster.name);
			    else if (ok)  // clusters they could activate for
				activatableClusters.add(cluster.name);
			}

			if (ok)
			    userAllowedClusters.add(cluster.name);
	    
		    }

		    // if just listing clusters they can login on, we're done. Don't want any actual changes
		    // no debug output because caller will do the output
		    // activatableClusters is a list to be returned for the "list" function
		    // so if it's set this is a list function
		    if (!cleanup && activatableClusters != null) {
			return true;
		    }

		    // if we're here we're doing activation or cleanup

		    Set<String> existingAutomaticGroups = user.makeExistingAutomaticGroups(config, action.val);

		    // add to groups that they should be in but aren't
		    Set<String> addGroups = new HashSet<String>();
		    addGroups.addAll(userMaintainedGroups);
		    addGroups.removeAll(existingAutomaticGroups);

		    // remove from groups that they are in but shouldn't be
		    Set<String> removeGroups = new HashSet<String>();
		    removeGroups.addAll(existingAutomaticGroups);
		    removeGroups.removeAll(userMaintainedGroups);

		    logger.debug("User should be in groups: " + userMaintainedGroups);
		    logger.debug("User is in manual groups: " + userManualLoginGroups);
		    logger.debug("User should be in clusters: " + userAllowedClusters);
		    logger.debug("Automatic groups user actually is a member of: " + existingAutomaticGroups);
		    logger.debug("Add to groups: " + addGroups);
		    logger.debug("Remove from groups: " + removeGroups);

		    String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/user/bin"};

		    // only activate if user is allowed for this cluster
		    // we shouldn't get called otherwise. We don't deactivate
		    // except as background job.
	
		    boolean ok = true;
	
		    // create user if necessary
		    // create groups if necessary
		    // add to groups
		    // add to login group
	
		    // create user if actually activing on a cluster and user doesn't exist
		    // userAllowedClusters.contains(requestedCluster) means he is allowed to be
		    //   on the cluster he's activating for.  You could argue we should create the
		    //   user if he can activate anywhere, but we don't really need the user until
		    //   he activates on a cluster where he can login
		    // we also don't create users for cleanup. We wait until they activate
		    if (!cleanup && action.val.size() == 0 && userAllowedClusters.contains(requestedCluster))
			ok = ok & createUser(username, config, universityData, test, logger, env);

		    // if user exists in both data, update attributes if any have changed
		    if (action.val.size() > 0 && lu.oneVal(universityData.get("uid")) != null)
			syncUser(username, config, universityData, action.val.get(0), test, logger, env);

		    // update all automatically maintained groups if user exists
		    if ((!cleanup && userAllowedClusters.contains(requestedCluster)) || action.val.size() > 0) {
			// want to update all groups as long as the user exists.
			// action.val.size() means they existed at the start of this process. If we're
			// not cleaning up, we will have created them if they didn't exist and they're supporsed to,
			//   so we just check whether they're supposed to exist

			// create groups if needed
			for (String addgroup: addGroups) {
			    if (!user.groupExists(addgroup, subj, config)) {
				logger.info("ipa group-add " + addgroup + " --nonposix");
				if (!test) {
				    if (docommand.docommand (new String[]{"/bin/ipa", "group-add", addgroup, "--nonposix"}, env) != 0)
					ok = false;
				}
			    }
			}		
			// add to groups if needed
			for (String addgroup: addGroups) {
			    logger.info("ipa group-add-member " + addgroup + " --users=" + username);
			    if (!test) {
				if (docommand.docommand (new String[]{"/bin/ipa", "group-add-member", addgroup, "--users=" + username}, env) != 0)
				    
				    ok = false;
			    }
			}

			// remove from groups if needed
			for (String removegroup: removeGroups) {
			    logger.info("ipa group-remove-member " + removegroup + " --users=" + username);
			    if (!test) {
				if (docommand.docommand (new String[]{"/bin/ipa", "group-remove-member", removegroup, "--users=" + username}, env) != 0)
				    ok = false;
			    }
			}
	    
		    }

		    // add to login group if needed, for activation
		    // will be false for cleanup, as requestedCluster is null
		    if (addtoCluster.contains(requestedCluster)) {
			if (!user.groupExists("login-" + requestedCluster, subj, config)) {
			    logger.info("ipa group-add login-" + addtoCluster + " --nonposix");
			    if (!test) {
				if (docommand.docommand (new String[]{"/bin/ipa", "group-add", "login-" + requestedCluster, "--nonposix"}, env) != 0)
				    ok = false;
			    }
			}
			logger.info("ipa group-add-member login-" + requestedCluster + " --users=" + username);
			if (!test) {
			    if (docommand.docommand (new String[]{"/bin/ipa", "group-add-member", "login-" + requestedCluster, "--users=" + username}, env) != 0)
				ok = false;	
			}
		    }

		    // remove from login groups for cleanup, including notification email
		    if (cleanup) {
			for (String cluster: removefromCluster) {
			    // file named user@cluster is used to remember we gave the warning
			    // we can remove the user when it's more than 60 days (or whatever) old
			    // name of file
			    String warningname = config.warningdir + "/" + username + "@" + cluster;
			    // nio Path for the file
			    Path warningPath = Paths.get(warningname);
			    boolean warned = Files.exists(warningPath);
			    if (config.warningdays > 0 && ! warned) {
				// if it doesn't exist, he wasn't warned, so we warn him and then create the file
				// cache the warning template
				if (user.warningtemplate == null)
				    user.warningtemplate = new String(Files.readAllBytes(Paths.get(config.warningtemplate)));
				// replace %c with cluster
				String message = user.warningtemplate.replaceAll("%c", cluster);
				// first line is subject, so separate into subject and message
				String [] parts = message.split("\n", 2);
				// default address. we hope to get a better one from ldap
				String toaddress = username + "@" + config.defaultmaildomain;
				if (universityData.get("mail") != null && universityData.get("mail").size() > 0)
				    toaddress = universityData.get("mail").get(0);
				// if email worked, create the file. The File.write call writers a zero length file
				logger.info("Sending notification to " + toaddress + " for " + cluster);
				if (!test) {
				    // for testing, can put a test address in config file. It will
				    // get all email rather than actual user
				    if (Mail.sendMail(config.fromaddress, (config.testaddress == null ? toaddress
 : config.testaddress), parts[0], parts[1]))
					Files.write(warningPath, new byte[]{});
				}
			    } else {
				// files exists, so they were warned. See if it's time to delete
				long now = System.currentTimeMillis();
				FileTime testtime = null;
				BasicFileAttributes attr = null;
				if (warned) {
				    testtime = FileTime.fromMillis(now - (config.warningdays * (24L * 60L * 60L * 1000L)));

				    attr = Files.readAttributes(warningPath, BasicFileAttributes.class);
				}
				if (config.warningdays == 0 || testtime.compareTo(attr.creationTime()) > 0) {
				    logger.info("ipa group-remove-member login-" + cluster + " --users=" + username);
				    if (!test) {
					if (docommand.docommand (new String[]{"/bin/ipa", "group-remove-member", "login-" + cluster, "--users=" + username}, env) == 0 && warned) {
					    Files.move(warningPath, Paths.get(warningname + ".done"), StandardCopyOption.REPLACE_EXISTING);
					}
				    }
				} else {
				    logger.info("User has been notified for " + cluster + " but it's not time to delete them");
				}
			    }				      
			}
		    }

		    if (cleanup) {
			if (!ok)
			    logger.error("Attempt to cleanup user " + username + " failed, at least in part");
		    } else 
			return ok;

		    // catch for one user
		} catch (Exception e) {
		    e.printStackTrace();
		    logger.error("unexpected exception while processing user " + username + " " + e);
		    if (!cleanup)
			return false;
		}

		if (cleanup)
		    logger.debug("");

	    }  // loop over users

	    return true;

	    // finally for whole process
	} finally {
	    if (config.csroleattr != null)
		db.closeDb();
	}

    }

}
