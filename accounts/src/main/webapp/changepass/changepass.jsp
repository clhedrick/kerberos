<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<%@ page import="java.util.Map" %>
<%@ page import="common.utils" %>
<head><link href="../usertool.css" rel="stylesheet" type="text/css">
</head>
<div id="masthead"></div>
<div id="main">
<a href="..">Account Management</a>

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

   String user = request.getRemoteUser();
   if (!utils.allowChangePassword(user)) {
      out.println("<p>You have previously requested that we disable this function for your account.<p>If you know your current password, you can use \"kpasswd\" on any of our systems.<p>If you've forgotten your password, please come in person to our help desk or systems staff.");
      return;
   }
   String cluster = filtername(request.getParameter("cluster"));
   if (cluster != null && cluster.trim().length() > 0) {
%>

<h2> Set password </h2>

<p> You have successfully created an account on cluster <%=cluster%>. In order
to login, you also need to create a password. This password will be good on 
systems in Computer Science labs and office. (In contrast, most of our
web applications use your University password.)

<p> It is preferable to use a password that's different from your University
password, but we're not going to force you to do that.

<% } else { %>

<h2> Password reset for Computer Science Dept password </h2>

<p> The Computer Science Department has passwords that are separate
from University passwords. This allows us to provide improved security
for your data.

<p>The CS Dept password is used for login to computers in labs and in offices. In contrast to these login passwords, most of our web applications use your University password. 

<p>This form allows you to change CS Dept password.

<p> We don't ask for your old password, because you have already logged in with
your University password.

<p> It is preferable to use a password that's different from your University
password, but we're not going to force you to do that.

<h2> How to change your password </h2>

<p> This web application lets you change your CS password as long as you
remember your University password. It's convenient if you forget your CS
password, or haven't set one up yet.

<p> If you remember your password, you can also change it on any CS system
that uses this passwords by using the command "kpasswd".

<% } %>

<h2> Password rules </h2>

<p>Our password rules follow the latest recommendations from the 
National Institute of Standards and Technology (NIST). These rules have changed
over time. E.g. NIST used to recommend forcing users to change their
passwords regularly, but they no longer do. Evidence suggests that
this isn't useful.

<ul>
<li> Passwords must be at least 10 characters. {The maximum is 255.)
<li> We do not require you to use multiple character classes, although we recommend it.
<li> Passwords must not match any entry in a list of commonly used passwords.
<li> Passwords do not expire, although we encourage you to change them
occasionally.
</ul>

<p>Good passwords:
<P>We recommend using a fairly long nonsense phrase. Experience with password cracking says that passphrases aren't necessarily
better than passwords if you pick actual phrases. Most people choose them from pop songs, movie titles, sports teams, Shakespeare, etc. They turn out to be easy to crack. Simply changing a few characters doesn't help that much. I recommend nonsense phrases not taken from any book, etc. Maybe even in a mix of languages.

<p>Other rules
<ul>
<li> If there are more than 6 bad passwords in a minute, the account will be locked for 10 minutes. This rule may change.
<li> If you change your password, we don't check whether you're changing it back to its current value (since we
don't force you to change it in the first place).
</ul>

<p> The final version of this page will generate a random pronouncable 
password, as a suggestion and probably suggestions for choosing a good password.

<h2> Change password here</h2>

<p>
<form action="changepass1.jsp" method="post">
<label>New password: <input type="password" name="pass1"/></label><br>
<label>Type it again to verify: <input type="password" name="pass2"/></label>
<p>
<input type="submit">
</form>


