<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ taglib prefix = "c" uri = "http://java.sun.com/jsp/jstl/core" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="Activator.User" %>
<%@ page import="common.utils" %>
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

   // set up model for JSTL
   // User.doUser calls the actual activator code to find out which clusters the user
   // is on and can activate on

   pageContext.setAttribute("ok", User.doUser(username, clusters, currentClusters, ineligibleClusters, null, false, false, true));
   pageContext.setAttribute("clusters", clusters);
   pageContext.setAttribute("currentClusters", currentClusters);
   pageContext.setAttribute("ineligibleClusters", ineligibleClusters);
   pageContext.setAttribute("helpmail", Activator.Config.getConfig().helpmail);

%>
<c:if test="${ok}">

<c:if test="${(clusters.size() + currentClusters.size() + ineligibleClusters.size() == 0)}">
<p> However according to our records, you are not authorized to create accounts
on any of our systems. If you think this is an error, please contact
<a href="mailto:${helpmail}"><c:out value="${helpmail}"/></a>. Make sure to
include your Netid, and the reason you should be eligible for an account.
</c:if>

<c:if test="${(clusters.size() + currentClusters.size() + ineligibleClusters.size() > 0)}">
<p> According to our records:

<c:if test="${currentClusters.size() > 0}">
<p> You currently have acounts on the following clusters of systems. You do not need to
do anything to continue using them.
<p> If you have forgotten your password, or you haven't created a password for the new systems,
use the <a href=../changepass/changepass.jsp> Change Password </a> screen.
<ul>
<c:forEach items="${currentClusters}" var="cluster">
<li><c:out value="${cluster}"/></a><br/>
</c:forEach>
</ul>
</c:if>

<c:if test="${clusters.size() > 0}">
<P> You can activate accounts 
on the following clusters of systems. Select the link to create
an account there:
<ul>
<c:forEach items="${clusters}" var="cluster">
<%-- this code assumes that cluster doesn't need quoting --%>
<li><a class="link" href="#" onclick="document.getElementById('form-${cluster}').submit();"><c:out value="${cluster}"/></a><br/>
<form style="display:none" id="form-${cluster}" action="activatecluster.jsp" method="post">
<%= utils.getCsrf(request) %>
<input type="hidden" name="cluster" value="${cluster}"/>
<input type="submit" value="submit"/></form>
</c:forEach>
</ul>
</c:if>

<c:if test="${ineligibleClusters.size() > 0}">
<P> You have accounts on the following cluster for which you are no longer eligible. You
should get email warning you that these accounts will be closed.  If you need to continue
using the accounts, please contact <a href="mailto:${helpmail}"><c:out value="${helpmail}"/></a>.
<ul>
<c:forEach items="${ineligibleClusters}" var="cluster">
<li><c:out value="${cluster}"/></a><br/>
</c:forEach>
</c:if>
</c:if>  <%-- end of at least one list is non-null --%>
</c:if>  <%-- end of if ok --%>

<c:if test="${!ok}">
<p> Unfortunately we are unable to determine where you are eligible for
accounts. Please contact <a href="mailto:${helpmail}"><c:out value="${helpmail}"/></a>. Make
sure to mention your netid in your email and any computer science courses you are taking.
</c:if>
