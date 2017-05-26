package common;
import java.io.*;
import javax.servlet.jsp.JspWriter;
import java.io.PrintStream;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.util.Arrays;

public class docommand {

    public static int docommand (String[]command, String[]env){
	return docommand(command, env, null);
    }
    public static int docommand (String[]command, String[]env, JspWriter out){
     
         Logger logger = null;
   	 logger = LogManager.getLogger();

         int retval = -1;
	 Process p = null;

	 try {
	     p = Runtime.getRuntime().exec(command, env);
	 } catch (Exception e) {
	     logger.error("unable to run command " + Arrays.toString(command) + " " + e);
             return -1;
	 }

	 try (
	      BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
	      BufferedReader reader2 = new BufferedReader(new InputStreamReader(p.getErrorStream()));
	      ) {
		 retval = p.waitFor();

		 // if it worked, no need to print a message
		 if (retval == 0)
		     return 0;

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
	     if (p != null)
		 p.destroy();
	 }

	 // if it worked, rename cc to its real name
	 // otherwise return fail.
         return retval;

   }

}
