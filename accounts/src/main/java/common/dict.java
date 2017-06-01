package common;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.IOException;
import java.sql.DriverManager;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.HashSet;
import common.lu;
import common.utils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.servlet.jsp.JspWriter;

public class dict {

     public static boolean checkdict(JspWriter out, String newpass) {

     Connection c = null;
     PreparedStatement pst = null;
     ResultSet rs = null;

     try {
         int count = 0;

	 Class.forName("org.hsqldb.jdbc.JDBCDriver" );

	 c = DriverManager.getConnection("jdbc:hsqldb:file:/var/www/tomcat/db/passwords;readonly=true", "SA", "");

//	 pst = c.prepareStatement("select count(*) from passwords where p = ? or p = ? or p = ? or p = ?");
//	 pst.setString(1, newpass);
//	 pst.setString(2, newpass.substring(1));
//	 pst.setString(3, newpass.substring(0,newpass.length()-1));
//	 pst.setString(4, newpass.substring(1,newpass.length()-1));
	 
	 pst = c.prepareStatement("select count(*) from passwords where p = ?");
         pst.setString(1, newpass);

	 rs = pst.executeQuery();
	 if (rs.next()) {
	     count = rs.getInt(1);
	 }
	 rs.close();
	 rs = null;

	 // if already have a match no need to reverse
//	 if (count == 0) {
//	     newpass = new StringBuffer(newpass).reverse().toString();
//	     pst.setString(1, newpass);
//	     pst.setString(2, newpass.substring(1));
//	     pst.setString(3, newpass.substring(0,newpass.length()-1));
//	     pst.setString(4, newpass.substring(1,newpass.length()-1));
	     
//	     rs = pst.executeQuery();
//	     if (rs.next()) {
//		 count = rs.getInt(1);
//	     }
//	 }

	 return count == 0;

     } catch (Exception e) {
	 try {
	     out.println("<p>Warning: we were unable to check your password to see if it matches any known weak passwords. We're allowing the change to happen, but you should make sure that your password is a good one.<p>");
	 } catch (Exception x) {};
	 return true;
     } finally {
	 try {
	     if (rs != null)
		 rs.close();
	 } catch (Exception ignore) {};
	 try {
	     if (pst != null)
		 pst.close();
	 } catch (Exception ignore) {};
	 try {
	     if (c != null)
		 c.close();
	 } catch (Exception ignore) {};
     }
     }
}


