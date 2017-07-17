package common;
import java.io.*;
import javax.servlet.jsp.JspWriter;
import java.io.PrintStream;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.List;
import java.util.ArrayList;
import java.util.Map;
import java.util.Set;

public class docommand {

    public static AtomicInteger commandIndex = new AtomicInteger(); // initialized to 0

    public static int docommand (String[]command, String[]env){
	return docommand(command, env, null);
    }
    public static int docommand (String[]command, String[]env, JspWriter out){
     
	boolean didincr = false;
         Logger logger = null;
   	 logger = LogManager.getLogger();

         int retval = -1;
	 Process p = null;

	 List<String> intEnv;
	 if (env == null) {
	     intEnv = new ArrayList<String>();
	     Set<Map.Entry<String, String>> envSet = System.getenv().entrySet();

	     for (Map.Entry<String, String> envEntry: envSet) {
		 intEnv.add(envEntry.getKey() + "=" + envEntry.getValue());
	     }
	 } else {
	     intEnv = new ArrayList<String>(Arrays.asList(env));
	 }

	 // if env ==  null, we got intenv from System.env, so it already
	 // has XDG_CACHE_HOME if any
	 if (System.getenv("XDG_CACHE_HOME") != null && env != null) {
	     intEnv.add("XDG_CACHE_HOME=" + System.getenv("XDG_CACHE_HOME"));
	 } else {
	     intEnv.add("XDG_CACHE_HOME=" + System.getProperty("user.home") + "/" + commandIndex.addAndGet(1));
	     didincr = true;
	 }

	 try {
	     p = Runtime.getRuntime().exec(command, intEnv.toArray(new String[intEnv.size()]));
	 } catch (Exception e) {
	     logger.error("unable to run command " + Arrays.toString(command) + " " + e);
	     if (didincr)
		 commandIndex.decrementAndGet();
             return -1;
	 }

	 try (
	      BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
	      BufferedReader reader2 = new BufferedReader(new InputStreamReader(p.getErrorStream()));
	      ) {
		 retval = p.waitFor();

		 // if it worked, no need to print a message
		 if (retval == 0) {
		     if (didincr)
			 commandIndex.decrementAndGet();
		     return 0;
		 }

		 logger.error("command returned " + retval + ": " + Arrays.toString(command));

		 String line=reader.readLine();
	       
		 while (line != null) {    
		     logger.error(line);
		     if (out != null)
			 out.println(StringEscapeUtils.escapeHtml4(line) + "<br/>");
		     line = reader.readLine();
		 }
		 
		 line=reader2.readLine();
		 while (line != null) {    
		     logger.error(line);
		     if (out != null)
			 out.println(StringEscapeUtils.escapeHtml4(line) + "<br/>");
		     line = reader.readLine();
		 }
	     }
	 catch(IOException e1) {
	     logger.error("Error talking to process to check password");
	 }
	 catch(InterruptedException e2) {
	     logger.error("Password check process interrupted");
	 }
	 finally {
	     if (didincr)
		 commandIndex.decrementAndGet();
	     if (p != null)
		 p.destroy();
	 }

	 // if it worked, rename cc to its real name
	 // otherwise return fail.
         return retval;

   }

}
