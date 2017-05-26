<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">

<%@ page import="javax.naming.*" %>
<%@ page import="javax.naming.directory.*" %>
<%@ page import="javax.naming.ldap.*" %>
<%@ page import="java.util.Hashtable" %>
<%@ page import="java.util.List" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.util.Collections" %>
<%@ page import="java.util.Comparator" %>
<%@ page import="java.util.ArrayList" %>
<%@ page import="java.util.Iterator" %>
<%@ page import="Activator.Config" %>
<%@ page import="Activator.Ldap" %>
<%@ page import="common.lu" %>
<%@ page import="org.apache.logging.log4j.LogManager" %>
<%@ page import="org.apache.logging.log4j.Logger" %>


<%! 

public static String listVal(List<String>vals) {
    if (vals == null || vals.size() == 0)
	return null;
    String ret = null;
    for (String val:vals) {
	if (ret == null)
	    ret = val;
	else
	    ret = ret + ", " + val;
    }
    return ret;
}

public String oneVal(List<String>vals) {
    if (vals == null || vals.size() == 0)
	return null;
    return vals.get(0);
}


class UserComparator implements Comparator {
    public int compare(Object x, Object y) {
	String [] a = (String []) x;
	String [] b = (String []) y;

	return a[0].compareToIgnoreCase(b[0]);
    }
}

   class NoFilterException extends Throwable {
	String my_error_message;
	public NoFilterException() { }
	public NoFilterException(String s) {
		my_error_message = s;
	}
	public String getMessage() {
		return my_error_message;
	}
   }



%>

<html>
<head>
<title>Rutgers User Lookup</title>
<link href="../usertool.css" rel="stylesheet" type="text/css">
<script type="text/javascript" src="../jquery-3.2.1.min.js" ></script>
</head>
<body>
<div id="masthead"></div>
<div id="main">
<script>
function choose(netid) {
       var textbox=window.opener.$(".newmember").last();
       if (!textbox.val()) {
	   textbox.val(netid);
	   window.opener.checknewmember();
       }
       return true;
}
</script>

<% 

       String netidadded = request.getParameter("netidadded");

  if (netidadded != null) { %>

<p>The NetID "<%= netidadded.replace("<", "&lt;").replace(">", "&gt;") %>" is now on the list of users to be added.
<p class="instruction">
You may now look up additional users, or click "Done looking up" if you have no more
users to add. 
<p class="instruction"> Clicking "Done looking up" will return you to "Add
Participants," where you can finish the process of adding the users
you have identified.
<p>&nbsp;

<% } 
if (request.getParameter("last") == null) { %>

<div class="portletMainWrap">
<div class="portletBody">
<h2>Rutgers User Lookup</h2>

<form action="addpart-lookup.jsp" method="post">

<p>
Last name: <input type=text name="last" size=40><br> 
First name: <input type=text name="first" size=40><br>
Anywhere in name: <input type=text name="anywhere" size=40><br>
Email address: <input type=text name="email" size=40><br>
NetID: <input type=text name="netid" size=10><br>
Rutgers ID: <input type=text name="ruid" size=12> [new ID number, not the SSN, no spaces or -]
<p>
<input type=submit value="Look up user">
<input type=button value='Done looking up' onclick='window.close()'>
</form>
<p>
<p class="instruction"> Enter just the information you know. Except for the NetID and Rutgers ID, we will match any value that starts with what you supply. Thus you can give an initial or the beginning of an email address.
<p class="instruction"> We can only look up email addresses that the user
has registered as their default mail address in the Rutgers Online Directory.
If someone
has given you an email address that doesn't match, try looking up the
part before the @ as a NetID.

<p class="instruction"> Searches ignore the difference between uppercase and lowercase.

<p class="instruction"> Some users have requested that their entries be
considered confidential. They will not show in this search. Users who have hidden
their email address will also not show.

</Div>
</div>

<% } %>

<% 
  String lastname = request.getParameter("last");
  String firstname = request.getParameter("first");
  String anywhere = request.getParameter("anywhere");
  String email = request.getParameter("email");
  String netidreq = request.getParameter("netid");
  String ruid = request.getParameter("ruid");
  String lookup = request.getParameter("lookup");
  String longformat = request.getParameter("longformat");

  boolean brief = longformat == null || longformat.equals("no");

  Object subject = request.getSession().getAttribute("krb5subject");
  if (subject == null) {
     out.println("<p>Sorry, you must be logged in to use this");
     return;
  } else
   if (netidadded == null && (lastname != null || firstname != null || anywhere != null || email != null || netidreq != null)) {


%>

<p> &nbsp;<p class="instruction">
Click on the button to the left of the name to add that person to the
list of new usernames. Once you are finished identifying people to add,
you will need to click "Done looking up", which will return you to "Add participants".
There you can finish the process of adding the users you have identified.
</p>

<form action="addpart-lookup.jsp" method="post">
<input type=hidden name="last" value="<%=lastname%>">
<input type=hidden name="first" value="<%=firstname%>">
<input type=hidden name="anywhere" value="<%=anywhere%>">
<input type=hidden name="email" value="<%=email%>">
<input type=hidden name="netid" value="<%=netidreq%>">
<input type=hidden name="ruid" value="<%=ruid%>">
<input type=hidden name="longformat" value=<%=(brief?"yes":"no")%>>
<input type=submit value="<%=(brief?"Show more information":"Show less information")%>">
</form>

<%

        String filter = null;

        filter = "(&";

	if (anywhere != null && !anywhere.trim().equals(""))
	   filter = filter + "(cn=*"+anywhere+"*)";
	if (lastname != null && !lastname.trim().equals(""))
	   filter = filter + "(sn="+lastname+"*)";
	if (firstname != null && !firstname.trim().equals(""))
	   filter = filter + "(givenname="+firstname+"*)";
	if (email != null && !email.trim().equals(""))
	   filter = filter + "(mail="+email+"*)";
	if (netidreq != null && !netidreq.trim().equals(""))
	   filter = filter + "(uid="+netidreq+")";
	if (ruid != null && !ruid.trim().equals(""))
	   filter = filter + "(rutgersEduRUID="+ruid+")";

	if (filter.equals("(&")) {
	    throw new NoFilterException();
	}	

        filter = filter + "(!(rulinkRutgersEduHidden=true))(rulinkRutgersEduStatus=active))";

	Logger logger = null;
	logger = LogManager.getLogger();

	Ldap ldap = new Ldap();

	Activator.Config xconfig = new Activator.Config();
	try {
	    xconfig.loadConfig();
	} catch (Exception e) {
	    logger.error("error loading config file " + e);
	    return;
	}


        List<Map<String,List<String>>> universityDataList = ldap.lookup(filter, xconfig);

        out.println("<form action='addpart-lookup.jsp' method='post'>");

        ArrayList<String[]> users = new ArrayList<String[]>();

        for (Map<String,List<String>> userData: universityDataList) {
            String netid = null;
            String cn = null;
            String sn = null;
            String address = null;
            String type = null;
            String unit = null;
            String month = null;
            String year = null;
            String mail = null;
            String roles = null;
            String phone = null;

	    netid = oneVal(userData.get("uid"));
	    roles = listVal(userData.get("employeetype"));
  	    cn = oneVal(userData.get("cn"));
  	    sn = oneVal(userData.get("sn"));
	    address = oneVal(userData.get("postaladdress"));
	    if (address != null && brief) {
		int j = address.indexOf("$");
		if (j >= 0)
		    address = address.substring(0, j);
	    }
  	    unit = oneVal(userData.get("rulinkrutgersedustudentunit"));	    
  	    month = oneVal(userData.get("rulinkrutgersedustudentgradmonth"));	    
	    year = oneVal(userData.get("rulinkrutgersedustudentgradyear"));	    
	    mail = oneVal(userData.get("mail"));	    
	    phone = oneVal(userData.get("telephonenumber"));	    

            if (unit != null && unit.endsWith(":"))
		unit = unit.substring(0, unit.length() - 1);

            if (sn != null) {
            // switch to last, first
            String fn, ln;
            int i = cn.indexOf(sn);
            if (i < 0)
		i = cn.lastIndexOf(" ");

            if (i >= 0) {
                ln = cn.substring(i);
                fn = cn.substring(0, i).trim();
                cn = ln;
                if (!fn.equals(""))
		    cn = ln + ", " + fn;
            }
           }
            String ident = cn;
            if (roles != null)
		ident = ident + " &#8212; " + roles + " ";
            if (unit != null || (month != null && year != null)) {
		ident = ident + " &#8212; ";
		if (unit != null)
		    ident = ident + unit + " ";
		if (month != null && year != null)
		    ident = ident + month + "/" + year + " ";
            }

            if (address != null)
		ident = ident + " &#8212; " + address + " ";
            if (mail != null)
		ident = ident + " &#8212; " + mail + " ";
            if (phone != null)
		ident = ident + " &#8212; " + phone + " ";

            // out.println("found " + ident);
            String[] u = {ident, "<input type=submit name=netidadded value='"+netid+"' onclick='choose(\""+netid+"\")'>"};

            users.add(u);

        }

        Comparator userComp = new UserComparator();

        Collections.sort(users, userComp);
        for (String[] user: users) {
            out.println(user[1].trim() + "&nbsp;&nbsp;&nbsp;&nbsp;" + user[0].trim() + "<br/>");
        }
        out.println("</form>");

    }

%>

<p>&nbsp;
<form action="addpart-lookup.jsp" method="post">

<p>
<input type=submit value="Look up another user">
<input type=button value='Done looking up' onclick='window.close()'>
</form>

<%


%>
<p>&nbsp;

</div>
</body></html>
