<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="java.util.List" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="Activator.User" %>
<%@ page import="common.utils" %>
<%@ page import="java.net.URLEncoder" %>
<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">
<a href="..">Account Management</a> | <a href="activate.jsp"> Activate accounts </a>
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

%>

<%

   String cluster = filtername(request.getParameter("cluster"));

   String username = request.getRemoteUser();
   if (username.equals("hedrick"))
      username = "dsmith";

   if (User.doUser(username, null, null, null, cluster, false, false, true)) {
      if (utils.needsPassword(username))
         response.sendRedirect("../changepass/changepass.jsp?cluster=" + URLEncoder.encode(cluster));

%>

<p> You have been properly activated on cluster <%= cluster %>. 

<p> NEXT STEP:

<ul>
<li> <a href="../changepass/changepass.jsp"> Set your Computer Science password here,</a>
if you are new to Computer Science systems, or you have forgotten your password.
Computer Science Department systems have a password that is separate from
your normal University password. 

<p>
<li> If you know your Computer Science password, you are finished,
or you can <a href="activate.jsp"> Activate an account on another cluster.</a>
</ul>
<%
   } else {
     String helpmail = Activator.Config.getConfig().helpmail;
%>
<p> Account activation failed. Please contact <a href="mailto:<%=helpmail%>"> <%=helpmail%></a> for help.
<%
   }

%>
