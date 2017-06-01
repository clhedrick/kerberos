<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="java.util.List" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="Activator.User" %>
<head><link href="../usertool.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="../jquery-3.2.1.min.js" ></script>
<script type="text/javascript">
var clicked = false;
$(document).ready(function(){
  $('.link').click(function(event){
     if (!clicked) {
       clicked = true;
     } else {
       event.preventDefault();
       alert('Please wait. This can take up to a minute.')
     }
  });

});
</script>
</head>
<div id="masthead"></div>
<div id="main">
<a href="..">Account Management</a>

<h2> Activate Account on Computer Science Dept systems </h2>

<p> This page will let you activate accounts on computer systems
within the Computer Science Department. You are eligible for an
account if you are computer science faculty, major, or grad student,
or if you are enrolled in computer science courses other than 110, 170, and 494. Some additional
types of users may be authorized on a special-case basis.

<%

   List<String> clusters = new ArrayList<String>();	    
   List<String> currentClusters = new ArrayList<String>();	    
   List<String> ineligibleClusters = new ArrayList<String>();	    
   String username = request.getRemoteUser();
   if (username.equals("hedrick"))
      username = "dsmith";

   String helpmail = Activator.Config.getConfig().helpmail;

   if (User.doUser(username, clusters, currentClusters, ineligibleClusters, null, false, false, true)) {
     if ((clusters.size() + currentClusters.size() + ineligibleClusters.size()) == 0 ) {
%>
<p> However according to our records, you are not authorized to create accounts
on any of our systems. If you think this is an error, please contact
<a href="mailto:<%=helpmail%>"><%=helpmail%></a>. Make sure to
include your Netid, and the reason you should be eligible for an account.
<%
     } else {
%>
<p> According to our records:
<%
       if (currentClusters.size() > 0) {
%>
<p> You currently have acounts on the following clusters of systems. You do not need to
do anything to continue using them.

<p> If you have forgotten your password, or you haven't created a password for the new systems,
use the <a href=../changepass/changepass.jsp> Change Password </a> screen.
<ul>
<%
	 for (String cluster: currentClusters) {
	   out.println("<li>" + cluster + "</a><br/>");
	 }
%>
</ul>
<%
       }
       if (clusters.size() > 0) {
%>

<P> You can activate accounts 
on the following clusters of systems. Select the link to create
an account there:
<ul>
<%
	 for (String cluster: clusters) {
	     out.println("<li><a class=\"link\" href=\"activatecluster.jsp?cluster=" + cluster + "\">" + cluster + "</a><br/>");
	 }
%>
</ul>
<%
       }
       if (ineligibleClusters.size() > 0) {
%>
<P> You have accounts on the following cluster for which you are no longer eligible. You
should get email warning you that these accounts will be closed.  If you need to continue
using the accounts, please contact <a href="mailto:<%=helpmail%>"><%=helpmail%></a>.
<ul>
<%
	 for (String cluster: ineligibleClusters) {
	   out.println("<li>" + cluster + "</a><br/>");
	 }
}
     }
   } else {
%>
<p> Unfortunately we are unable to determine where you are eligible for
accounts. Please contact <a href="mailto:<%=helpmail%>"><%=helpmail%></a>. Make
sure to mention your netid in your email and any computer science courses you are taking.
<%
   }
%>
