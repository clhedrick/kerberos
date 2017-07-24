<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="javax.security.auth.*" %>
<%@ page import="javax.security.auth.callback.*" %>
<%@ page import="javax.security.auth.login.*" %>
<%@ page import="javax.naming.*" %>
<%@ page import="javax.naming.directory.*" %>
<%@ page import="javax.naming.ldap.*" %>
<%@ page import="java.io.*" %>
<%@ page import="com.sun.security.auth.callback.TextCallbackHandler" %>
<%@ page import="java.util.Hashtable" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Arrays" %>
<%@ page import="java.util.Set" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="org.apache.commons.lang3.StringEscapeUtils" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="common.docommand" %>
<%@ page import="common.JndiAction" %>
<%@ page import="common.lu" %>
<%@ page import="common.utils" %>
<%@ page import="Activator.Ldap" %>
<%@ page import="Activator.Config" %>
<%@ page import="Activator.Uid" %>
<%@ page import="Activator.User" %>
<%@ page import="org.apache.logging.log4j.LogManager" %>
<%@ page import="org.apache.logging.log4j.Logger" %>



<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">
<a href="showgroups.jsp">Group list</a>
<p>

<%!

   public String filtername(String s) {
       if (s == null)
	   return null;
       String ret = s.replaceAll("[^-_.a-z0-9]","");
       if (ret.equals(""))
	   return null;
       return ret;
   }

     public boolean assureUser(JspWriter out, HttpServletRequest request, String name, boolean createOk) {
       Logger logger = null;
       logger = LogManager.getLogger();
       Config conf = Config.getConfig();

       try {
	 // if user isn't in our system, add them
	 Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
	 if (subject == null) {
	     out.println("<p>Session has expired<p><a href=\"login.jsp\"> Try again</a>");
	     return false;
	 }
	 String kname = (String)request.getSession().getAttribute("krb5user");

	 common.JndiAction action = new common.JndiAction(new String[]{"(uid=" + name + ")", "", "uid"});

	 Subject.doAs(subject, action);
	 if (action.val == null || action.val.size() == 0) {
	     if (!createOk) {
		 out.println("<p>User " + name + " isn't in our system.");
		 return false;
	     }

	     Activator.Ldap ldap = new Activator.Ldap();
	     List<Map<String,List<String>>> universityDataList = ldap.lookup("(uid=" + name + ")", conf);
	     Map<String,List<String>> universityData = null;

	     // can't create an account without university data, but in cleanup I guess it could happen
	     // so create empty data
	     if (universityDataList == null || universityDataList.size() == 0) {
		 out.println("<p>" + name + ": Can only add a netid that is in the University's data");
		 return false;
	     }
	     universityData = universityDataList.get(0);
	     String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/user/bin"};
             return User.createUser(name, conf, universityData, false, logger, env);

	 }
	 return true;

       } catch (Exception e) {
	   logger.error("Failure in assureUser " + e);
	   try {
	       out.println("<p>Unexpected failure checking for User " + name);
	   } catch (Exception ignore) {}
	   return false;
       }

     }


%>

<%

   utils.checkCsrf(request);

   Logger logger = null;
   logger = LogManager.getLogger();

   String oname = request.getParameter("name");
   String name = filtername(request.getParameter("groupname"));
   if (oname != null && !"".equals(oname) && !oname.equals(name)) {
      out.println("Name of group should contain only digits, lowercase letters, period, _, and -");
      out.println("<p><a href=\"showgroups.jsp\">Try again</a>");
      return;
   }

// this JNDI thing is to do an LDAP query
// we need current value of login properties so we
// know what to change

class JndiAction implements java.security.PrivilegedAction {
    private String[] args;
    public boolean islogin = false;
    public ArrayList<String> hosts = new ArrayList<String>();
    public ArrayList<String> members = new ArrayList<String>();
    public ArrayList<String> owners = new ArrayList<String>();
    public boolean valid = false;

    public JndiAction(String[] origArgs) {
	this.args = (String[])origArgs.clone();
    }

    public Object run(){
	performJndiOperation(args);
	return null;
    }

    private void performJndiOperation(String[] args){

        String gname = args[0];

	// Set up environment for creating initial context
	Hashtable env = new Hashtable(11);

        Activator.Config conf = Activator.Config.getConfig();
   

	env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
	env.put(Context.PROVIDER_URL, conf.kerbldapurl);
	env.put(Context.SECURITY_AUTHENTICATION, "GSSAPI");

        DirContext ctx = null;

	try {
	    ctx = new InitialDirContext(env);

            String[] attrIDs = {"host", "businesscategory", "member", "owner"};

	    String filter = "(&(objectclass=groupofnames)(cn=" + gname + "))";

            SearchControls ctls = new SearchControls();
            ctls.setReturningAttributes(attrIDs);
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);

	    NamingEnumeration answer =
		ctx.search("", filter, ctls);

            if (!answer.hasMore()) {
		return;
	    }
	    SearchResult sr = (SearchResult)answer.next();
	    if (answer.hasMore()) {
		return;
	    }
	    // have exactly one answer.
	    valid = true;
	    Attributes attributes = sr.getAttributes();
	    Attribute busAt = attributes.get("businesscategory");
	    if (busAt != null && busAt.contains("login"))
		islogin = true;
	    
	    Attribute hostAt = attributes.get("host");
	    if (hostAt != null) {
		NamingEnumeration<String> hostvals = (NamingEnumeration<String>)hostAt.getAll();
		while (hostvals.hasMore())
		    hosts.add(hostvals.next());
	    }
	    Attribute memberAt = attributes.get("member");
	    if (memberAt != null) {
		NamingEnumeration<String> membervals = (NamingEnumeration<String>)memberAt.getAll();
		while (membervals.hasMore())
		    members.add(lu.dn2user(membervals.next()));
	    }

	    Attribute ownerAt = attributes.get("owner");
	    if (ownerAt != null) {
		NamingEnumeration<String> ownervals = (NamingEnumeration<String>)ownerAt.getAll();
		while (ownervals.hasMore())
		    owners.add(lu.dn2user(ownervals.next()));
	    }

	} catch (NamingException e) {
	    e.printStackTrace();
	} finally {
	    try {
		ctx.close();	    
	    } catch (Exception ignore) {};
        }
    }
}

   Config conf = Config.getConfig();

// Get current values of login attributes so we know what to change.
// They show up as values of variables in action

   JndiAction action =  new JndiAction(new String[]{name});

   Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
   if (subject == null) {
      out.println("<p>Session has expired<p><a href=\"login.jsp\"> Try again</a>");
      return;
   }

   Subject.doAs(subject, action);

   if (!action.valid) {
      out.println("Unable to find group");
      out.println("<p><a href=\"showgroups.jsp\">Try again</a>");
   }

   boolean ok = true;

   String user = (String)request.getSession().getAttribute("krb5user");

   String env[] = {"KRB5CCNAME=/tmp/krb5cc_" + user, "PATH=/bin:/user/bin"};

   String del[] = request.getParameterValues("del"); 
   if (del != null && del.length != 0) {
     for (int i = 0; i < del.length; i++) {
	 logger.info("ipa group-remove-member " + name + " --users=" + filtername(del[i]));
	 if (docommand.docommand (new String[]{"/bin/ipa", "group-remove-member", name, "--users=" + filtername(del[i])}, env, out) != 0)
	     ok = false;
     }
   }

   String add[] = request.getParameterValues("newmember"); 
   if (add != null && add.length != 0) {
     for (int i = 0; i < add.length; i++) {
	 if (add[i] != null && !add[i].equals("")) {
	     if (action.members.contains(add[i])) {
		 out.println("<p> User " + lu.esc(add[i]) + " is already in the group.");
		 ok = false;
	     } else if (!assureUser(out, request, filtername(add[i]), action.islogin))
		 ok = false;
	     else {
		 logger.info("ipa group-add-member " + name + " --users=" + filtername(add[i]));
		 if (docommand.docommand (new String[]{"/bin/ipa", "group-add-member", name, "--users=" + filtername(add[i])}, env, out) != 0)
		     ok = false;
	     }
	 }
     }
   }

   del = request.getParameterValues("delowner"); 
   if (del != null && del.length != 0) {
     for (int i = 0; i < del.length; i++) {
	 logger.info("ip group-mod " + name + " --delattr=owner=uid=" + filtername(del[i]) + conf.usersuffix);
	 if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=owner=uid=" + filtername(del[i]) + conf.usersuffix}, env, out) != 0)
	     ok = false;
     }
   }

   add = request.getParameterValues("newowner"); 
   if (add != null && add.length != 0) {
     for (int i = 0; i < add.length; i++) {
	 if (add[i] != null && !add[i].equals("")) {
	     if (action.owners.contains(add[i])) {
		 out.println("<p> User " + lu.esc(add[i]) + " is already an owner.");
		 ok = false;
		 continue;
	     } else if (!assureUser(out, request, filtername(add[i]), false)) {
		 ok = false;
		 continue;
	     }
	     logger.info("ipa group-mod " + name + " --addattr=owner=uid=" + filtername(add[i]) + conf.usersuffix);	     
	     if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=owner=uid=" + filtername(add[i]) + conf.usersuffix}, env, out) != 0)
		 ok = false;
	 }
     }
   }

   String loginSt = request.getParameter("login");
   boolean login = "on".equals(loginSt);

   if (login && !action.islogin) {
       logger.info("ipa group-mod " + name + " --addattr=businessCategory=login");
       if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=businessCategory=login"}, env, out) != 0)
	   ok = false;
   } else if (!login && action.islogin) {
       logger.info("ipa group-mod " + name + " --delattr=businessCategory=login");
       if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=businessCategory=login"}, env, out) != 0)
	   ok = false;
   }

   ArrayList<String> clusters = new ArrayList<String>();

   Config aconfig = new Config();
   try {
       aconfig.loadConfig();
   } catch (Exception e) {
       out.println("<p> Unable to load configuration.");
       return;
   }

   for (Config.Cluster cluster: aconfig.clusters)
       clusters.add(cluster.name);

   String hosts[] = request.getParameterValues("hosts"); 
   List<String>newhosts = null;
   if (hosts == null)
       newhosts = new ArrayList<String>();
   else
       newhosts = Arrays.asList(hosts);

   for (String cluster: clusters) {
       if (newhosts.contains(cluster) && !action.hosts.contains(cluster)) {
	   logger.info("ipa group-mod " + name + " --addattr=host=" + cluster);
	   if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--addattr=host=" + cluster}, env, out) != 0)
	       ok = false;
       } else if (!newhosts.contains(cluster) && action.hosts.contains(cluster)) {
	   logger.info("ipa group-mod " + name + " --delattr=host=" + cluster);
	   if (docommand.docommand (new String[]{"/bin/ipa", "group-mod", name, "--delattr=host=" + cluster}, env, out) != 0)
	       ok = false;
       }
   }

   if (ok)
       response.sendRedirect("showgroup.jsp?name=" + URLEncoder.encode(name));

%>

       <p>Operation failed. If you need further explanation, please contact <a href="mailto:<%=conf.helpmail%>"><%=conf.helpmail%></a>

<p><a href="showgroup.jsp?name=<%= URLEncoder.encode(name) %>">Try again</a>.

