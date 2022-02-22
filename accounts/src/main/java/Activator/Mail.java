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
import Activator.Config;
import java.util.*;
import java.io.File;
import jakarta.mail.Transport;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.Message;
import jakarta.mail.Message.RecipientType;
import jakarta.mail.Session;
import org.simplejavamail.utils.mail.dkim.DkimSigner;
import org.simplejavamail.utils.mail.dkim.DkimMessage;
import org.simplejavamail.utils.mail.dkim.Canonicalization;
import org.simplejavamail.utils.mail.dkim.SigningAlgorithm;


public class Mail {



    public static boolean sendMail(String from, String replyto, String to, String subject, String body) {
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

	    // Reply-to
	    if (replyto != null)
		message.setHeader("Reply-To", replyto);

	    // Set To: header field of the header.
	    message.addRecipient(RecipientType.TO, new InternetAddress(to));

	    // Set Subject: header field
	    message.setSubject(subject);

	    // Now set the actual message
	    message.setText(body);

	    String dkimkey = Config.getConfig().dkimkey;
	    String dkimselector = Config.getConfig().dkimselector;
	    String dkimdomain = Config.getConfig().dkimdomain;
	    if (dkimkey != null && dkimselector != null && dkimdomain != null & from.endsWith(dkimdomain)) {
		DkimSigner dkimSigner = new DkimSigner(dkimdomain, dkimselector, new File(dkimkey));
		dkimSigner.setIdentity(from);
		dkimSigner.setHeaderCanonicalization(Canonicalization.SIMPLE);
		dkimSigner.setBodyCanonicalization(Canonicalization.RELAXED);
		dkimSigner.setSigningAlgorithm(SigningAlgorithm.SHA256_WITH_RSA);
		dkimSigner.setLengthParam(true);
		dkimSigner.setCopyHeaderFields(false);

		// DkimMessage is in fact of type Message, but the compiler
		// doesn't realize it, so do this at runtime
		Object signed = new DkimMessage(message, dkimSigner);
		if (signed instanceof Message) {
		    Message m = (Message) signed;
		    Transport.send(m);
		    System.out.println("Sent DKIM message");
		}
		//	    Class C = signed.getClass();
		//	    while (C != null) {
		//		System.out.println(C.getName());
		//		C = C.getSuperclass();
		//	    }
	    
	    } else {
		Transport.send(message);
		System.out.println("Sent unsigned message");
	    }

	}catch (Exception mex) {
	    mex.printStackTrace();
	    return false;
	}
	return true;
    }

    public static void main(String [] args) {    
	String from = Config.getConfig().fromaddress;
	String replyto = Config.getConfig().replytoaddress;

	sendMail(from, replyto, "hedrick@cs.rutgers.edu", "test message", "This is a test from java");
    }

}
