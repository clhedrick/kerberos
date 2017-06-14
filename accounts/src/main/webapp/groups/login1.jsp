<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="javax.security.auth.*" %>
<%@ page import="javax.security.auth.callback.*" %>
<%@ page import="javax.security.auth.login.*" %>
<%@ page import="java.io.*" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="com.sun.security.auth.callback.TextCallbackHandler" %>
<%@ page import="javax.naming.*" %>
<%@ page import="javax.naming.directory.*" %>
<%@ page import="javax.naming.ldap.*" %>
<%@ page import="java.util.Hashtable" %>
<%@ page import="common.JndiAction" %>
<%@ page import="common.utils" %>
<%@ page import="Activator.Config" %>
<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">

<%!

     // This process is harder than it ought to because of the JAAS API
     // In addition to normal JAAS stuff we need two things:

     // makeCC - does the actual login by calling skinit, returned a cred cache in temp
     //   We can't use the normal JAAS login because it doesn't understand one time passwords

     // KerberosConfiguration - JAAS normaly wants a config file. But that would result in using
     //   the same credential cache file for all users. This class generates a cache name based
     //   on the username.

     // makeCC
     // Do the login and return a credentials cache

     static String makeCC (JspWriter out, String user, String pass) throws java.io.IOException {
     
         int retval = -1;
	 // create temporary cc and rename it for two reasons:
	 //   want to make sure we can tell if login worked. skinit may return ok even if it fails.
	 //      but if it fails it won't create the temporary cache.
	 //   want to avoid race condition if there's a second process using it. atomic rename is
	 //      safer than overwriting
	 String tempcc = "/tmp/krb5cc_" + user + "_" + java.lang.Thread.currentThread().getId();
	 String cc = "/tmp/krb5cc_" + user;
	 // will rename if it succeeds

         String [] cmd = {"/usr/local/bin/skinit", "-l", "1d", "-c", tempcc, user};
       
	 Process p = null;
	 try {
	     p = Runtime.getRuntime().exec(cmd);
	 } catch (Exception e) {
	     out.println("unable to run skinit: " + e);
	 }

	 try (
	      PrintWriter writer = new PrintWriter(p.getOutputStream());
	      ) {
		 writer.println(pass);
		 writer.close();
		 retval = p.waitFor();
	       
		 // we're not giving any error messages
		 if (retval != 0)
		     out.println("Bad username or password");
	       
	     }
	 catch(IOException e1) {
	     out.println("Error talking to process to check password");
	 }
	 catch(InterruptedException e2) {
	     out.println("Password check process interrupted");
	 }
	 finally {
	     p.destroy();
	 }

	 // if it worked, rename cc to its real name
	 // otherwise return fail.
	 if (retval == 0) {
	     try {
		 new File(tempcc).renameTo(new File(cc));
		 return cc;
	     } catch (Exception e) {
		 return null;
	     }
	 } else {
	     try {
		 new File(tempcc).delete();
	     } catch (Exception e) {
	     }
	     return null;
	 }

   }

   // protect against unreasonable usernames

   public String filteruser(String s) {
       if (s == null)
	   return null;
       String ret = s.replaceAll("[^-_.a-z0-9]","");
       if (ret.equals(""))
	   return null;
       return ret;
   }
   public String filterpass(String s) {
       if (s == null)
	   return null;
       String ret = s.replaceAll("[\r\n]","");
       if (ret.equals(""))
	   return null;
       return ret;
   }



%>
<%

   utils.checkCsrf(request);

   // KerberosConfiguration
   //  generates a config on the fly rather than the default of reading it from a file
   //  expects the cache to be /tmp/krb5cc_USERNAME

   class KerberosConfiguration extends Configuration { 
        private String cc;
 
        public KerberosConfiguration(String cc) { 
            this.cc = cc;
        } 
 
        @Override 
        public AppConfigurationEntry[] getAppConfigurationEntry(String name) { 
            Map<String, String> options = new HashMap<String, String>(); 
            options.put("useTicketCache", "true"); 
            options.put("refreshKrb5Config", "true"); 
	    options.put("ticketCache", cc);
 
            return new AppConfigurationEntry[]{ 
		new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
					  AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, 
					  options),}; 
        } 
    } 


 // Main code

 // get and validate arguments

  LoginContext lc = null;
  String username = filteruser(request.getParameter("user"));
  String password = filterpass(request.getParameter("pass"));

  if (!username.equals(request.getParameter("user"))) {
      out.println("Bad username or password");
      out.println("<p><a href=\"login.jsp\">Try again</a>");
      return;
  }

  // make credentials cache   

  String cc = makeCC (out, username, password);
  if (cc == null) {
      // should have gotten error message already
      out.println("<p><a href=\"login.jsp\">Try again</a>");
      return;
  }

  // do the actuall login. Output is a Subject.

  Configuration kconfig = new KerberosConfiguration(cc);
  try {
      lc = new LoginContext("Groups", null, null, kconfig);
      lc.login();
  } catch (LoginException le) {
      out.println("Cannot create LoginContext. " + le.getMessage());
      out.println("<p><a href=\"login.jsp\">Try again</a>");
      return;
  } catch (SecurityException se) {
      out.println("Cannot create LoginContext. " + se.getMessage());
      out.println("<p><a href=\"login.jsp\">Try again</a>");
      return;
  }

  Subject subj = lc.getSubject();  
  if (subj == null) {
      out.println("Login failed");
      out.println("<p><a href=\"login.jsp\">Try again</a>");
  }

  // the following JndAction will verify that they're in the right group,

   
   Config conf = Config.getConfig();
   String filter = conf.groupmanagerfilter.replaceAll("%u", username);

   // this action isn't actually done until it's called by doAs. That executes it for the Kerberos subject using GSSAPI
   common.JndiAction action = new common.JndiAction(new String[]{filter, "", "uid"});

   Subject.doAs(subj, action);

   // look at the result of the LDAP query. Query needs to find the user, which verifies that they're in the group
   if (action.val.size() >= 1) {
      request.getSession().setAttribute("krb5subject", subj);
      request.getSession().setAttribute("krb5user", username);
      response.sendRedirect("showgroups.jsp");
  } else {
      out.println("You're not authorized to manaage groups. If you should be, please send email to " + conf.helpmail + ".");
      out.println("<p><a href=\"login.jsp\">Try again</a>");
      return;
  } 


%>
