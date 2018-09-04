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

package Activator;
import java.util.*;
import javax.mail.*;
import javax.mail.internet.*;
import javax.activation.*;


public class Mail {

    public static boolean sendMail(String from, String to, String subject, String body) {
	// Assuming you are sending email from localhost
	String host = Config.getConfig().mailhost;

	// Get system properties
	Properties properties = System.getProperties();

	// Setup mail server
	properties.setProperty("mail.smtp.host", host);

	// Get the default Session object.
	Session session = Session.getDefaultInstance(properties);

	try {
	    // Create a default MimeMessage object.
	    MimeMessage message = new MimeMessage(session);

	    // Set From: header field of the header.
	    message.setFrom(new InternetAddress(from));

	    // Set To: header field of the header.
	    message.addRecipient(Message.RecipientType.TO, new InternetAddress(to));

	    // Set Subject: header field
	    message.setSubject(subject);

	    // Now set the actual message
	    message.setText(body);

	    // Send message
	    Transport.send(message);
	    //	    System.out.println("Sent message successfully....");
	}catch (MessagingException mex) {
	    mex.printStackTrace();
	    return false;
	}
	return true;
    }

    public static void main(String [] args) {    
	sendMail("hedrick@rutgers.edu", "hedrick@cs.rutgers.edu", "test message", "This is a test from java");
    }

}
