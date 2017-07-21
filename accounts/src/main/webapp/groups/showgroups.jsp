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
<%@ page import="common.utils" %>
<%@ page import="common.JndiAction" %>

<head><link href="../usertool.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="../jquery-3.2.1.min.js" ></script>
<script type="text/javascript">
function deletegroup(event) {
  var group = $(event.target).next().val();
  if (!confirm("Are you sure you want to delete this group?"))
    return;
  $("#deleteInput").val(group);
  $("#deleteSubmit").click();
}

function deleteKeyPress(event) {
  // Check to see if space or enter were pressed
  if (event.keyCode === 32 || event.keyCode === 13) {
    // Prevent the default action to stop scrolling when space is pressed
    event.preventDefault();
    deletegroup(event);
  }
}

function validateSubmit(event) {
  if (! ($("#sharing").prop("checked") || $("guests").prop("checked"))) {
    alert("Sharing and/or guests must be checked");
    event.preventDefault();
    return;
  }
  if ($("#name").val() == '') {
    alert("Name for the new group must be supplied");
    event.preventDefault();
    return;
  }
}

$(document).ready(function(){
    $(".deleteButton").click(deletegroup);
    $(".deleteButton").keypress(deleteKeyPress);
    $("#submit").click(validateSubmit);
    });

</script>
</head>
<div id="masthead"></div>
<div id="main">
<a href="../"> Account Management</a>

<h2> Group Management </h2>

<p> These pages can be used to create and manage groups for sharing files, and also to authorize guest users.

<form action="groupchange.jsp" method="post" id="deleteForm" style="display:none">
<%= utils.getCsrf(request) %>
<input type="text" name="del" id="deleteInput"/>
<input type="submit" id="deleteSubmit"/>
</form>

<form action="groupchange.jsp" method="post">
<%= utils.getCsrf(request) %>
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

<div class="inset" style="padding-top:0.5em">

<% for (HashMap<String, ArrayList<String>> group: groups) { String name=lu.oneVal(group.get("cn")); %>

<a href="showgroup.jsp?name=<%= URLEncoder.encode(name) %>"><%= lu.esc(name) %></a> <%= (lu.hasVal(group.get("gidnumber")) ? lu.esc(lu.oneVal(group.get("gidnumber"))) : "") %><img role="button" tabindex="0" style="height:1em;margin-left:1em" src="delete.png" title="Delete group <%= lu.esc(name) %>" class="deleteButton"><input type="hidden" name="deleteName" value="<%= lu.esc(name) %>"><br>

<% }} %>
</div>

<h3 style="margin-top:2em"> Add Group </h3>

<div class="inset" style="margin-top:1em">
<label>Group Name: <input type="text" name="name" id="name"/></label>
<br>
<label><input type="checkbox" name="sharing" id="sharing"> Group should be available for file sharing.</label>
<br>
<label><input type="checkbox" name="guests" id="guests"> Users in group may be guests. Accounts for them will be added if they don't already exist.</label>
<p>
<input type="submit" id="submit">
</div>
</form>
<div class="explanation" style="margin-top:2em">
<p> When adding a group, at least one of the boxes should be checked. 
<p> "Users in group may be guests" means that members of this group
are alloweed as guests, even if they wouldn't normally be able to login.
If you edit the group, you'll be able to choose which clusters they can
login to.
</div>
