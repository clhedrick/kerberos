<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="java.io.BufferedReader" %>
<%@ page import="java.io.InputStreamReader" %>
<%@ page import="java.io.PrintWriter" %>
<%@ page import="java.io.IOException" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.CallableStatement" %>
<%@ page import="java.sql.Connection" %>
<%@ page import="java.sql.DriverManager" %>
<%@ page import="java.sql.PreparedStatement" %>
<%@ page import="java.sql.ResultSet" %>
<%@ page import="java.sql.SQLException" %>
<%@ page import="java.sql.Types" %>
<%@ page import="java.util.HashSet" %>
<%@ page import="common.lu" %>
<%@ page import="common.utils" %>
<%@ page import="common.dict" %>
<%@ page import="org.apache.commons.lang3.StringEscapeUtils" %>
<%@ page import="org.apache.logging.log4j.LogManager" %>
<%@ page import="org.apache.logging.log4j.Logger" %>

<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">

<%

   Logger logger = null;
   logger = LogManager.getLogger();

// remoteuser should be the CAS authenticated user.
// so the only argument is the new password

   String newpass = request.getParameter("pass1");
   String newpass2 = request.getParameter("pass2");
   String user = request.getRemoteUser();
   int retval = -1;

   if (!utils.allowChangePassword(user)) {
      out.println("<p>You have requested that we disable automatic password changes for your account. Please come in person to our help desk or systems staff to change your password.");
      return;
   }

// stupid. to simulate goto
   while (true) {

       if (newpass == null) {
	   out.println("<p>No password specified<p>");
	   break;
       }

       if (!newpass.equals(newpass2)) {
	   out.println("<p>Your two copies of the password don't match<p>");
	   break;
        }

       String testpass = newpass.toLowerCase();

       if (testpass.length() < 10) {
	   out.println("<p>Password must be at least 10 characters<p>");
	   break;
       }

       if (!dict.checkdict(out, testpass)) {
	   logger.info("User " + user + " new password in dictionary");
	   out.println("<p>Password is in our dictionary of common passwords<p>");
	   break;
       }

//       if (!checkchars(out, testpass)) {
//	   out.println("<p>Password must have at least 6 different characters<p>");
//	   break;
//       }

       if ("hedrick".equals(user))
	   user = "clh";
       else if ("makmur".equals(user))
	   user = "hmakmur";
       else if ("watrous".equals(user))
	   user = "daw";

       String [] cmd = {"/bin/ipa", "passwd", user};
       
       logger.info("ipa passwd " + user);

       Process p = Runtime.getRuntime().exec(cmd);
       try (
	    PrintWriter writer = new PrintWriter(p.getOutputStream());
	    BufferedReader reader2 = new BufferedReader(new InputStreamReader(p.getErrorStream()));
	    ) {
	       writer.println(newpass);
	       writer.println(newpass);
	       writer.close();
	       retval = p.waitFor();

	       // 2 is non-existent user. We have our eown error for that.
	       // otherwise give them the actual error
			       
	       if (retval != 0 && retval != 2) {
		   String line=reader2.readLine();

		   out.println("<p>");
		   while (line != null) {    
		       out.println(lu.esc(line) + "<br/>");
		       logger.error(line);
		       line = reader2.readLine();
		   }
	       }
	       reader2.close();

	   }
       catch(IOException e1) {
	   logger.error("Error talking to process to change password");
	   out.println("<p>Error talking to process to change password<p>");
       }
       catch(InterruptedException e2) {
	   logger.error("Password change process interrupted");
	   out.println("<p>Password change process interrupted<p>");
       } 
       finally {
	   p.destroy();
       }

       if (retval == 2) {
	   logger.info("User " + user + " attempted password change but not in our system");
	   out.println("<p>You don't have a computer science account. If you are eligible, please register at URL.<p>");
	   break;
       }
       if (retval == 0) {
	   logger.info("User " + user + " password change ok");
	   out.println("<p>Password changed.");
	   break;
       }

       // another error. message already printed
       break;
   }

%>

<p>
<ul>
<% if (retval != 0) { %>
<li><a href="changepass.jsp"> Try again </a>
<%}%>
<li><a href="../index.jsp"> Account Management </a>
</ul>


