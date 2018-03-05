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

package application;

import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Date;
import java.net.URLEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.format.annotation.DateTimeFormat;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import common.utils;
import common.genpassword;
import common.dict;
import common.lu;
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
import java.util.List;
import java.util.ArrayList;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Controller
public class ChangepassController {

    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^-_.a-z0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    @GetMapping("/changepass/changepass")
    public String changepassGet(@RequestParam(value="cluster", required=false) String cluster,
				HttpServletRequest request, HttpServletResponse response, Model model) {
	String user = request.getRemoteUser();

	model.addAttribute("allowchange", utils.allowChangePassword(user));
	String pass = genpassword.generate(10);
	for (int i = 0; i < 1000; i++) {
	    if (dict.checkdict(null, pass)) {
		model.addAttribute("suggestion", pass);
		break;
	    }
	    pass = genpassword.generate(10);          
	}

	model.addAttribute("cluster", filtername(cluster));

        return "changepass/changepass";
    }

    @PostMapping("/changepass/changepass")
    public String changepassSubmit(@RequestParam(value="pass1") String newpass,
				   @RequestParam(value="pass2") String newpass2,
				   HttpServletRequest request, HttpServletResponse response,
				   Model model) {
	Logger logger = null;
	logger = LogManager.getLogger();

	// remoteuser should be the CAS authenticated user.
	// so the only argument is the new password

	String user = request.getRemoteUser();
	int retval = -1;
	if ("hedrick".equals(user))
	    user = "clh";

	List<String> messages = new ArrayList<String>();

	// stupid. to simulate goto
	while (true) {

	    if (!utils.allowChangePassword(user)) {
		messages.add("You have requested that we disable automatic password changes for your account. Please come in person to our help desk or systems staff to change your password.");
		break;
	    }

	    if (newpass == null) {
		messages.add("No password specified");
		break;
	    }

	    if (!newpass.equals(newpass2)) {
		messages.add("Your two copies of the password don't match");
		break;
	    }

	    String testpass = newpass.toLowerCase();

	    if (testpass.length() < 10) {
		messages.add("Password must be at least 10 characters");
		break;
	    }
	    
	    if (!dict.checkdict(null, testpass)) {
		logger.info("User " + user + " new password in dictionary");
		messages.add("Password is in our dictionary of common passwords");
		break;
	    }

//       if (!checkchars(out, testpass)) {
//	   out.println("<p>Password must have at least 6 different characters<p>");
//	   break;
//       }

	    if ("hedrick".equals(user))
		user = "clh";
	    else if ("makmur".equals(user))
		user = "hmakmur";
	    else if ("watrous".equals(user))
		user = "daw";

	    String [] cmd = {"/bin/ipa", "passwd", user};
	    
	    logger.info("ipa passwd " + user);

	    Process p = null;
	    try {
		String env[] = {"KRB5CCNAME=/tmp/krb5ccservices", "PATH=/bin:/usr/bin"};
		p = Runtime.getRuntime().exec(cmd, env);
		try (
		     PrintWriter writer = new PrintWriter(p.getOutputStream());
		     BufferedReader reader2 = new BufferedReader(new InputStreamReader(p.getErrorStream()));
		     ) {
			writer.println(newpass);
			writer.println(newpass);
			writer.close();
			retval = p.waitFor();
			
			// 2 is non-existent user. We have our eown error for that.
			// otherwise give them the actual error
			
			if (retval != 0 && retval != 2) {
			    String line=reader2.readLine();
			    
			    while (line != null) {    
				messages.add(line);
				logger.error(line);
				line = reader2.readLine();
			    }
			}
			reader2.close();
			
		    }
		catch(IOException e1) {
		    logger.error("Error talking to process to change password");
		    messages.add("Error talking to process to change password");
		}
		catch(InterruptedException e2) {
		    logger.error("Password change process interrupted");
		    messages.add("Password change process interrupted");
		} 
	    } catch(Exception e) {
		logger.error("Unable to execute ipa password command");
		messages.add("Unable to execute ipa password command");
	    } finally {
		if (p != null)
		    p.destroy();
	    }

	    if (retval == 2) {
		logger.info("User " + user + " attempted password change but not in our system");
		break;
	    }
	    if (retval == 0) {
		logger.info("User " + user + " password change ok");
		messages.add("Password changed.");
		break;
	    }
	    
	    // another error. message already printed
	    break;
	}

	model.addAttribute("messages", messages);
	model.addAttribute("retval", retval);

	return changepassGet(null, request, response, model);

    }

}
