<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="javax.security.auth.*" %>
<%@ page import="javax.security.auth.callback.*" %>
<%@ page import="javax.security.auth.login.*" %>
<%@ page import="javax.naming.*" %>
<%@ page import="javax.naming.directory.*" %>
<%@ page import="javax.naming.ldap.*" %>
<%@ page import="com.sun.security.auth.callback.TextCallbackHandler" %>
<%@ page import="java.util.Hashtable" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Set" %>
<%@ page import="org.apache.commons.lang3.StringEscapeUtils" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="common.lu" %>
<%@ page import="common.utils" %>
<%@ page import="common.JndiAction" %>

<head><link href="../usertool.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="../jquery-3.2.1.min.js" ></script>
<script type="text/javascript">
function checknewmember() {
     var hasempty = false;
     $(".newmember").each(function() {
	     if (!$(this).val())
		 hasempty = true;
	 });
     if (!hasempty) {
	 $(".newmember").last().parent().after("<br/><label>User name to add as member: <input class=\"newmember\" type=\"text\" name=\"newmember\"></label>");
	 $(".newmember").change(checknewmember);
     }
 };

$(document).ready(function(){
    $(".newmember").change(checknewmember);
    });

function checknewowner() {
     var hasempty = false;
     $(".addowner").each(function() {
	     if (!$(this).val())
		 hasempty = true;
	 });
     if (!hasempty) {
	 $(".addowner").last().parent().after("<br/><label>User name to add as owner: <input class=\"addowner\" type=\"text\" name=\"newowner\"></label><br>");

	 $(".addowner").change(checknewowner);
     }
 };

$(document).ready(function(){
    $(".addowner").change(checknewowner);
    });

</script>
</head>
<div id="masthead"></div>
<div id="main">
<a href="../"> Account Management</a> | <a href="showgroups.jsp">Group list</a>

<h2> Show and Edit Group </h2>



<form action="editgroup.jsp" method="post">
<%= utils.getCsrf(request) %>
<%

 // This module uses Kerberized LDAP. The credentials are part of a Subject, which is stored in the session.
 // This JndiAction junk is needed to execute the LDAP code in a context that's authenticated by
 // that Subject.

// To separate logic from display, I've implemented my own API on top of the Sun LDAP code
// It uses a class JndiAction that does an LDAP query and returns
//   ArrayList<HashMap<String, ArrayList<String>>>
// This is a list of things found by the query. For a lookup of a specific user or group the list will have just one member.
// Each memory is a hashmap, with the key being attributes and the value a list of results.
// E.g. map.get("uid") would get you the value of the uid attribute. Because some attributes can have more
// than one value, the map returns a list of strings, not just one.
//
// There are set of conveninece methods in common.lu:
// lu.oneVal can be used to return one value for attributes that have only one value, e.g. 
//    String gid = lu.oneVal(attrs.get("gid"));
//   the advatnage over attrs.get("gid").get(0) is that it won't blow up if there's no value. It returns null, so
//   you should normally check with hasVal first
// lu.hasVal checks whether the value is non-null and has at least one item
// lu.valList return the list of values. lu.valList(attrs.get("member"));
//    all it does it protect against nulls, so if there's no member attribute you get an empty list rather than null
// lu.esc is just an abbreviatio for the incredibly verbose StringEscapeUtils.escapeHtml4
// lu.dn2user converts a dn to a username. If the dn starts with uid=XXXX, it returns XXXX. 
//    otherwise it returns the whole dn

// In case you're not familiar with JSP syntax, <% introduces full java logic. Use it for if tests, for loops, etc.
// <%= prints a value. It's like <% out.println(  

Subject subject = (Subject)request.getSession().getAttribute("krb5subject");
if (subject == null) {
    out.println("<p>Session has expired<p><a href=\"login.jsp\"> Try again</a>");
    return;
}

String gname = request.getParameter("name");

// This acton isn't done until it's called by doAs
common.JndiAction action = new common.JndiAction(new String[]{"(&(objectclass=groupofnames)(cn=" + gname + "))", "", "cn", "member", "host", "businessCategory", "dn", "gidNumber", "owner", "creatorsName"});

// this is part of the Kerberos support. Subject is the internal data structure representing a Kerberos ticket.
// doas does an action authenticated as that subject. The action has to be a JndiAction. I supply a JndiAction does does
// an LDAP query, but you could do anything that uses GSSAPI authentication.
Subject.doAs(subject, action);

if (action.val.size() != 1) {
    out.println("<p> Group not found.");
    return;
}

HashMap<String, ArrayList<String>> attrs = action.val.get(0);

String gid = lu.oneVal(attrs.get("gidnumber"));
if (gid == null)
    gid = "";
else
    gid = ", " + gid;


List<String>categories = attrs.get("businesscategory");
boolean islogin = (categories != null && categories.contains("login"));

List<String> clusters = new ArrayList<String>();
clusters.add("ilab");
clusters.add("grad");

List<String> hosts = lu.valList(attrs.get("host"));

%>

<input type="hidden" name="groupname" value="<%=lu.esc(gname)%>">
<p> Group: <%= lu.esc(gname) %><%= gid %>

<% if (lu.hasVal(attrs.get("member"))) { %>
<h3>Members</h3>

<% for (String m: attrs.get("member")) { String member = lu.dn2user(m); %>
<%= lu.esc(member) %> <input type="checkbox" name="del" value="<%= lu.esc(member) %>" title="Delete member <%= lu.esc(member) %>"> <br>
<% }} %>

<h3>Add member</h3>
<label>User name to add as member: <input class="newmember" type="text" name="newmember"></label> <a href="addpart-lookup.jsp" target="addpart"> Lookup up usser</a><br>

<% if (lu.hasVal(attrs.get("creatorsname")) || lu.hasVal(attrs.get("owner"))) { %>
<h3>Owners</h3>

<% if (lu.hasVal(attrs.get("creatorsname"))) {  %>
<%= lu.esc(lu.dn2user(lu.oneVal(attrs.get("creatorsname")))) %><br>
<% } %>

<% if (attrs.get("owner") != null) { for (String o: attrs.get("owner")) { String owner = lu.dn2user(o); %>
<%= lu.esc(owner) %> <input type="checkbox" name="delowner" value="<%= lu.esc(owner) %>" title="Delete owner <%= lu.esc(owner) %>"><br>

<% }}} %>

<h3>Add Owner</h3>
<label>User name to add as owner: <input class="addowner" type="text" name="newowner"></label><br>

<h3>Login Ability</h3>

<p><label><input type="checkbox" name="login" <%= (islogin ? "checked" : "") %>> Members of group can login to specified clusters<p>
<% for (String c: clusters) { %>
<label><input type="checkbox" name="hosts" value="<%=c%>" <%= (hosts.contains(c) ? "checked" : "") %>> <%= c %><br>
<% } %>

<p>
<input type="submit">
</form>
