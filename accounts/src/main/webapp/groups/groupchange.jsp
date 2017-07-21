<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="javax.security.auth.*" %>
<%@ page import="javax.security.auth.callback.*" %>
<%@ page import="javax.security.auth.login.*" %>
<%@ page import="javax.naming.*" %>
<%@ page import="javax.naming.directory.*" %>
<%@ page import="javax.naming.ldap.*" %>
<%@ page import="java.io.*" %>
<%@ page import="java.text.SimpleDateFormat" %>
<%@ page import="java.util.Date" %>
<%@ page import="java.util.Locale" %>
<%@ page import="java.util.TimeZone" %>
<%@ page import="com.sun.security.auth.callback.TextCallbackHandler" %>
<%@ page import="java.util.Hashtable" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="org.apache.commons.lang3.StringEscapeUtils" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="common.docommand" %>
<%@ page import="common.utils" %>
<%@ page import="Activator.Config" %>
<%@ page import="org.apache.logging.log4j.LogManager" %>
<%@ page import="org.apache.logging.log4j.Logger" %>

<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">

<%!

   public String filtername(String s) {
       if (s == null)
	   return null;
       String ret = s.replaceAll("[^-_.a-z0-9]","");
       if (ret.equals(""))
	   return null;
       return ret;
   }

%>

<%

   utils.checkCsrf(request);

   Logger logger = null;
   logger = LogManager.getLogger();

   Config conf = Config.getConfig();

   String oname = request.getParameter("name");
   String name = filtername(request.getParameter("name"));
   if (oname != null && !"".equals(oname) && !oname.equals(name)) {
      out.println("Name of new group should contain only digits, lowercase letters, period, _, and -");
      out.println("<p><a href=\"showgroups.jsp\">Try again</a>");
      return;
   }
   if (name != null)
      name = name.toLowerCase().trim();

   String sharingSt = request.getParameter("sharing");
   boolean sharing = "on".equals(sharingSt);
   String guestSt = request.getParameter("guests");
   boolean guests = "on".equals(guestSt);

   if (name != null && !sharing && !guests) {
      out.println("Sharing or guests (or both) must be specified for the new group");
      out.println("<p><a href=\"showgroups.jsp\">Try again</a>");
      return;
   }



   boolean ok = true;

   String user = (String)request.getSession().getAttribute("krb5user");

   String env[] = {"KRB5CCNAME=/tmp/krb5cc_" + user, "PATH=/bin:/user/bin"};

   String del[] = request.getParameterValues("del"); 
   if (del != null && del.length != 0) {
     for (int i = 0; i < del.length; i++) {
	 // don't check for failure. We get a spruious failure because it tries to
	 // delete a non-existent Kerberos policy entry
	 logger.info("ipa group-del " + del[i]);
	 docommand.docommand(new String[]{"ipa", "group-del", del[i]}, env);
     }
   }

   if (name != null && !"".equals(name)) {
       name = name.toLowerCase();
       if (conf.reservedgroups != null) {
	   String [] reserved = conf.reservedgroups.split(",");
	   for (int i = 0; i < reserved.length; i++) {
	       if (name.matches(reserved[i].trim())) {
		   out.println(name + " is a reserved name");
		   return;
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
       if (docommand.docommand(command.toArray(new String[1]), env) != 0)
	   ok = false;

   }

   if (ok)
       response.sendRedirect("showgroups.jsp");

   out.println("<p><a href=\"showgroups.jsp\">Group list</a>");

%>
