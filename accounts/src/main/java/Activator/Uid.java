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
import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.util.Map;
import java.util.HashMap;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/*
 * Get uid from uidtable. This is a fairly exact translations of the
 * perl code in LibActivate2.pm, since we need them to interoperate.
 */

public class Uid {
    public static FileLock getLock(FileChannel channel) {
	var limit = 60; // 2 minutes, since it's 60 * 2000
	while (true) {
	    try {
		FileLock lock = channel.lock();
		return lock;
	    } catch (java.nio.channels.OverlappingFileLockException ignore) {
		// ignore, will try again
	    } catch (Exception e) {
	         throw new java.lang.IllegalArgumentException("problem locking uidtable " + e);
	    }

	    limit --;
	    if (limit <= 0)
		throw new java.lang.IllegalArgumentException("problem locking uidtable; OverlappingFileLockException too many times");
	    // I think this happens onky for that exception. Other exceptions
	    // won't be caught, and thus will trickle up
	    try {
		Thread.sleep(2000);
	    } catch (java.lang.InterruptedException e) {
		throw new java.lang.IllegalArgumentException("problem locking uidtable; some other thread interrupted our sleep");
	    }

	}	 
    }

    public static long allocateUid(String netid, Config config) {
	try (
	     RandomAccessFile file = new RandomAccessFile(config.uidtable, "rw");
	     FileChannel channel = file.getChannel();
	     FileLock lock = getLock(channel);
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

    // maps university netids like mysql to a local equivalent, e.g. cs-mysql
    public static String localUid(String netid, Config config) {
	// if no mapping table, just return the netid
	if (config.baduidtable == null)
	    return netid;
	// else read the file and map it
	Charset charset = Charset.forName("US-ASCII");
	try (BufferedReader reader = Files.newBufferedReader(Paths.get(config.baduidtable), charset)) {
		String line = null;
		while ((line = reader.readLine()) != null) {
		    int i = line.indexOf(":");
		    if (i < 1) {
			// no colon, prohibited uid without replacement
			if (netid.equals(line.trim()))
			    return null;
		    } else if (netid.equals(line.substring(0,i).trim())) {
			// prohibited uid with replacement, use replacement
			return line.substring(i+1).trim();
		    }
		}
	    } catch (IOException x) {}
	return netid;
    }

    
    // returns map from CS username to university netid, just where they are different
    public static Map<String,String> local2Univ(Config config) {
        Map<String,String> retMap = new HashMap<String,String>();
	// if no mapping table, just return the netid
	if (config.baduidtable == null)
	    return retMap;
	// else read the file and map it
	Charset charset = Charset.forName("US-ASCII");
	try (BufferedReader reader = Files.newBufferedReader(Paths.get(config.baduidtable), charset)) {
		String line = null;
		while ((line = reader.readLine()) != null) {
		    int i = line.indexOf(":");
		    if (i < 1)
			continue;
		    retMap.put(line.substring(i+1).trim(), line.substring(0,i).trim());
		}
	    } catch (IOException x) {}
	return retMap;
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
