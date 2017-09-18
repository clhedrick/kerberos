/*
 * Copyright 2017 by Rutgers, the State University of New Jersey
 * All Rights Reserved.
 *
 * Permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of Rutgers not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original Rutgers software.
 * Rutgers makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 */

package common;
import javax.security.auth.*;
import javax.security.auth.callback.*;
import javax.security.auth.login.*;
import javax.naming.*;
import javax.naming.directory.*;
import javax.naming.ldap.*;
import com.sun.security.auth.callback.TextCallbackHandler;
import java.util.Hashtable;
import java.util.HashMap;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.apache.commons.lang3.StringEscapeUtils;

public class lu {
     public static String oneVal(List<String> vals) {
	 return oneVal(vals, null);
     }

     public static String oneVal(List<String> vals, String def) {
         if (vals == null)
	     return def;
	 if (vals.size() == 0)
	     return def;
	 if (vals.get(0).length() == 0)
	     return def;
	 return vals.get(0);
     }


     public static boolean hasVal(List<String> vals) {
	 if (vals == null)
	     return false;
	 if (vals.size() == 0)
	     return false;
	 return true;
     }

     public static List<String> valList(List<String> vals) {
	 if (vals == null)
	     return new ArrayList<String>();
	 else
	     return vals;
     }
     public static String esc(String s) {
	 return StringEscapeUtils.escapeHtml4(s);
     }

     public static String dn2user(String s) {
	 if (s == null)
	     return "";
	 if (s.startsWith("uid=")) {
	     s = s.substring(4);
	     int i = s.indexOf(",");
	     if (i > 0)
		 s = s.substring(0, i);
	 }
	 return s;
     }
	 
     public static String dn2cn(String s) {
	 if (s == null)
	     return "";
	 if (s.startsWith("cn=")) {
	     s = s.substring(3);
	     int i = s.indexOf(",");
	     if (i > 0)
		 s = s.substring(0, i);
	 }
	 return s;
     }

}
