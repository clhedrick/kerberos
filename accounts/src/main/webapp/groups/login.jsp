<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">

<%@ page import="java.util.Map" %>
<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">

<% if (request.getSession().getAttribute("krb5subject") != null) response.sendRedirect("showgroups.jsp"); %>
  


<h2> Group management for Computer Science systems </h2>

<p> This application will allow you to create and manage
user groups. These can be used to share files among a group of
people. For authorized people (usually faculty) you can also
allow members of the groups to login to systems they wouldn't
normally have access to.

<p> This login uses your computer science department password,
which may be different from your University password.

<p> You must have specific authorization for this to work. Faculty
should have it. If you're faculty and aren't authorized, or if you're not faculty and need
to authorize guests or manage project groups, please send a request
to <%=Activator.Config.getConfig().helpmail%>.


<h2> Login</h2>

<p>
<form action="login1.jsp" method="post">
Username: <input type="text" name="user"/><br/>
Password: <input type="password" name="pass"/>
<p>
<input type="submit">
</form>


