<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="javax.security.auth.*" %>
<%@ page import="javax.security.auth.callback.*" %>
<%@ page import="javax.security.auth.login.*" %>
<%@ page import="javax.naming.*" %>
<%@ page import="javax.naming.directory.*" %>
<%@ page import="javax.naming.ldap.*" %>
<%@ page import="javax.security.auth.kerberos.KerberosTicket" %>
<%@ page import="com.sun.security.auth.callback.TextCallbackHandler" %>
<%@ page import="java.util.Hashtable" %>
<%@ page import="java.util.Set" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="org.apache.commons.lang3.StringEscapeUtils" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="common.lu" %>
<%@ page import="common.JndiAction" %>

<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">
<a href="../"> Account Management</a>

<h2> Group Management </h2>

<p> These pages can be used to create and manage groups for sharing files, and also to authorize guest users.

<form action="groupchange.jsp" method="post">
<%

 // This module uses Kerberized LDAP. The credentials are part of a Subject, which is stored in the session.
 // This JndiAction junk is needed to execute the LDAP code in a context that's authenticated by
 // that Subject.

Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
if (subject == null) {
    out.println("<p>Session has expired<p><a href=\"login.jsp\"> Try again</a>");
    return;
}

// I use an API I wrote around Sun's API support.
// See comments on showgroup.jsp

String user = (String)request.getSession().getAttribute("krb5user");

String query = Activator.Config.getConfig().groupsownedfilter.replaceAll("%u", user);

// this action isn't actually done until it's called by doAs. That executes it for the Kerberos subject using GSSAPI
common.JndiAction action = new common.JndiAction(new String[]{query, "", "cn","dn", "gidNumber"});

Subject.doAs(subject, action);

// look at the results of the LDAP query
ArrayList<HashMap<String, ArrayList<String>>> groups = action.val;


%>

<% if (groups.size() > 0) { %>

<h3>Current groups owned by you</h3>

<p>Check box to delete a group, then hit submit<p>

<% for (HashMap<String, ArrayList<String>> group: groups) { String name=lu.oneVal(group.get("cn")); %>

<a href="showgroup.jsp?name=<%= URLEncoder.encode(name) %>"><%= lu.esc(name) %></a> <%= (lu.hasVal(group.get("gidnumber")) ? lu.esc(lu.oneVal(group.get("gidnumber"))) : "") %> <input type="checkbox" name="del" value="<%= lu.esc(name) %>" title="Delete group <%= lu.esc(name) %>"><br>

<% }} %>

<h3> Add Group </h3>

<label>Group Name: <input type="text" name="name"/></label>
<br>
<label><input type="checkbox" name="sharing"> Group should be available for file sharing.</label>
<br>
<label><input type="checkbox" name="guests"> Users in group should be able to login.</label>
<p>
<input type="submit">
</form>

<p> When adding a group, at least one of the boxes should be checked. 
<p> If you want to allow people to be able to login
to a cluster, check "Users in group may be guests." You should then edit the group to indicate
which clusters they can use.

