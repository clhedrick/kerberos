<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<script>
if (!location.pathname.endsWith("/") && !location.pathname.endsWith("index.jsp") || !location.protocol=='https') {
   location.href = 'https:' + location.host + "/" + location.pathname + "/";
}
</script>
<style type="text/css">^
 hr {border:none; border-top: dotted black 2px; margin-left:1em; margin-right: \
1em}
.textblock {
-moz-border-radius: 1em;
-webkit-border-radius: 1em;
border-radius: 1em;
padding:0em 1em 0em 1em;
border: solid black 1px;
background-color: #ffffdd;
}
.textblock2 {
background-color: #eeeeee;
}
</style>
<head><link href="usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">

<h2> Account Management Tools for<br>Computer Science Systems</h2>

<p><span style="color:#c00"> WARNING: </span> These tools work with a new account management
system. No public CS computers currently use these passwords and groups. The first clusters
to be moved to this system will be grad and ilab, in the summer of 2017.
<p>
For details on the new system see <a href="kerberos.html">Computer Science Department user administration tools</a>

<ul>
<li> <a href="activate/activate.jsp">Activate an account on a Computer Science system</a>
<p>
This will let you create an account for Computer Science Department systems. Computer science
faculty, majors, grad students, and students enrolled in computer science courses other than 110, 170 and 494
are eligible for accounts.
<p>
<li> <a href="changepass/changepass.jsp">Set or reset your Computer Science  password</a>. 
<p>
This will show you a University login screen. So as long as you remember
your University password, you set or reset your CS password. If you need more security than a simple password
can afford, please see <a href="two-factor.html"> two factor authentication</a>.
<li> <a href="groups/login.jsp">Group management.</a> This will let authorized users (typically faculty) create user groups for computer science systems. This will let you share files with other people and authorize guest users.
<p>
This will show you a Computer Science login screen.
<li> <a href="<%=Activator.Config.getConfig().usermgmturl%>">Kerberos user management (two factor authentication).</a> This lets you look for users and change your own
user information. Note that the information here isn't really visible to anyone. So the only real usefulness of this
tool is the ability to enable two factor authentication for your account. See <a href="two-factor.html"> two factor authentication</a> for specifics. This page will show you a Computer Science login screen. If you have trouble with the web application, the <a href="two-factor.html"> two-factor web page</a> gives instructions for enabling it from the command line.
</ul>
<div class="textblock" style="margin-top:3em">
<p>NOTE on <b>cron jobs</b>: For systems that use these accounts, 
cron jobs need special attentino. If you're using cron, and you want
your jobs to access files in your home directory, you must use
"kgetcred -r" on each host where you're going to use cron. See "man kgetcred"
for more information. 
</div>
