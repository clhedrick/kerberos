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
import java.io.*;
import javax.servlet.jsp.JspWriter;
import java.io.PrintStream;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;


public class docommand {

    public static ConcurrentSkipListSet<Integer> cachesUsed = new ConcurrentSkipListSet<Integer>();

    public static int docommand (String[]command, String[]env){
	return docommand(command, env, null, null);
    }
    public static int docommand (String[]command, String[]env, JspWriter out){
	return docommand(command, env, out, null);
    }
    public static int docommand (String[]command, String[]env, List<String> outlist){
	return docommand(command, env, null, outlist);
    }

    public static int docommand (String[]command, String[]env, JspWriter out, List<String> outlist){
	return docommand(command, env, out, outlist, false);
    }
    
    public static int docommand (String[]command, String[]env, JspWriter out, List<String> outlist, boolean alwaysout){
     
 	 Integer cacheUsed = null;
         Logger logger = null;
   	 logger = LogManager.getLogger();

         int retval = -1;
	 Process p = null;

	 // IPA doesn't synchronize its cache. So if we run two copies at once,
	 // the cache could get corrupted. We can fix this by using different
	 // values of "XDG_CACHE_HOME". If the user has specified it as an
	 // environment variable, we just use it. Otherwise we generate a name.
	 // To get the most caching, we want to reuse names. So we allocate 
	 // numerical names, and use the first one that's free. Use a
	 // concurrent set to keep track of what's in use.


	 // if "XDG_CACHE_HOME" is specified and we're using system env,
	 // nothing to do, so skip this absurd code
	 if (System.getenv("XDG_CACHE_HOME") == null || env != null) {
	     // can't add stuff to either the env array or the map that comes from System.getenv
	     // so we convert to an arrayList, and then back to an array
	     List<String> envList;
	     if (env == null) {
		 // using system env, so convert it
		 envList = new ArrayList<String>();
		 Set<Map.Entry<String, String>> envSet = System.getenv().entrySet();
		 for (Map.Entry<String, String> envEntry: envSet) {
		     envList.add(envEntry.getKey() + "=" + envEntry.getValue());
		 }
	     } else {
		 envList = new ArrayList<String>(Arrays.asList(env));
	     }

	     // now have the environment in envList. Add "XDG_CACHE_HOME"
	     if (System.getenv("XDG_CACHE_HOME") != null)
		 envList.add("XDG_CACHE_HOME=" + System.getenv("XDG_CACHE_HOME"));
	     else {
		 // need to find the first free 
		 // not sure whether we should put a limit here or not. 100 sees safe
		 for (cacheUsed = 0; cacheUsed < 100; cacheUsed++) {
		     if (cachesUsed.add(cacheUsed))
			 break;
		 }
		 // we now have the first free cache in cacheUsed
		 envList.add("XDG_CACHE_HOME=" + System.getProperty("user.home") + "/" + cacheUsed);
	     }

	     // have full env, convert list back to array
	     env = envList.toArray(new String[envList.size()]);
	 }

	 try {
	     p = Runtime.getRuntime().exec(command, env);
	 } catch (Exception e) {
	     logger.error("unable to run command " + Arrays.toString(command) + " " + e);
	     if (cacheUsed != null)
		 cachesUsed.remove(cacheUsed);
             return -1;
	 }

	 try (
	      BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
      BufferedReader reader2 = new BufferedReader(new InputStreamReader(p.getErrorStream()));
	      ) {
		 retval = p.waitFor();

		 // if it worked, no need to print a message
		 if (retval == 0 && ! alwaysout) {
		     return 0;
		 }

		 if (outlist == null)
		     logger.error("command returned " + retval + ": " + Arrays.toString(command));

		 String line=reader.readLine();
	       
		 while (line != null) {    
		     if (outlist == null)
			 logger.error(line);
		     if (out != null)
			 out.println(StringEscapeUtils.escapeHtml4(line) + "<br/>");
		     if (outlist != null)
			 outlist.add(line);
		     line = reader.readLine();
		 }
		 
		 line=reader2.readLine();
		 while (line != null) {    
		     if (outlist == null)
			 logger.error(line);
		     if (out != null)
			 out.println(StringEscapeUtils.escapeHtml4(line) + "<br/>");
		     if (outlist != null)
			 outlist.add(line);
		     line = reader2.readLine();
		 }
	     }
	 catch(IOException e1) {
	     logger.error("Error talking to process to check password");
	 }
	 catch(InterruptedException e2) {
	     logger.error("Password check process interrupted");
	 }
	 finally {
	     if (cacheUsed != null)
		 cachesUsed.remove(cacheUsed);
	     if (p != null)
		 p.destroy();
	 }

	 // if it worked, rename cc to its real name
	 // otherwise return fail.
         return retval;

   }

}
