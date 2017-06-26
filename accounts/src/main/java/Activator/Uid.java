package Activator;
import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/*
 * Get uid from uidtable. This is a fairly exact translations of the
 * perl code in LibActivate2.pm, since we need them to interoperate.
 */

public class Uid {
    public static long allocateUid(String netid, Config config) {
	try (
	     RandomAccessFile file = new RandomAccessFile(config.uidtable, "rw");
	     FileChannel channel = file.getChannel();
	     FileLock lock = channel.lock();
	     ) {
		String line;
		String [] atoms = null;
		long uid = -1;

		while ((line = file.readLine()) != null) {
		    atoms = line.split(":", 2);
		    // skip blank line
		    if (line.trim().equals(""))
			continue;
		    if (atoms.length < 2){ 
			throw new java.lang.IllegalArgumentException("bad line in uidtable " + line);
		    }
		    try {
			uid = Long.parseLong(atoms[1].trim());
		    } catch (Exception e) {
			throw new java.lang.IllegalArgumentException("bad uid in uidtable " + line);
		    }
		    if (atoms[0].trim().equals(netid))
			return uid;

		}
		file.seek(file.length());
		// if we got here didn't find it
		// reader is locked already. But need to open for append
		file.writeBytes(netid + ":" + (uid + 1) + "\n");
		return uid+1;
	    } catch (Exception e) {
	         throw new java.lang.IllegalArgumentException("problem reading uidtable " + e);
	    }
    }	       

    public static void main( String[] args) {
	Config config = new Config();
	try {
	    config.loadConfig();
	} catch (Exception e) {
	    System.out.println("error " + e);
	}

	System.out.println(allocateUid(args[0], config));
    }

}
