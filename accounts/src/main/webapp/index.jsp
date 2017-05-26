<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<script>
if (!location.pathname.endsWith("/") && !location.pathname.endsWith("index.jsp") || !location.protocol=='https') {
   location.href = 'https:' + location.host + "/" + location.pathname + "/";
}
</script>
<head><link href="usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">

<h2> Account Management Tools for<br>Computer Science Systems</h2>

<span style="color:#c00"> WARNING: </span> These tools work with a new account management
system. No public CS computers currently use these passwords and groups. The first clusters
to be moved to this system will be grad and ilab, in the summer of 2017.

<ul>
<li> <a href="activate/activate.jsp">Activate an account on a Computer Science system</a>
<p>
This will let you create an account for Computer Science Department systems. Computer science
faculty, majors, grad students, and students enrolled in computer science courses other than 110, 170 and 494
are eligible for accounts.
<p>
</P>
<li> <a href="changepass/changepass.jsp">Change your Computer Science  password</a>. 
<p>
This will show you a University login screen. So as long as you remember
your University password, you can change your CS password.
<li> <a href="groups/login.jsp">Group management.</a> This will let authorized users (typically faculty) create user groups for computer science systems. This will let you share files with other people and authorize guest users.
<p>
This will show you a Computer Science login screen.
<li> <a href="<%=Activator.Config.getConfig().usermgmturl%>">Kerberos user management.</a> This lets you look for users and change your own
user information. Note that the information here isn't really visible to anyone. So the only real usefulness of this
tool is the ability to enable two factor authentication for your account.
<p>
This will show you a Computer Science login screen.
</ul>
