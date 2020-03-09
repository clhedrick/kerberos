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
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.HashSet;
import java.util.Set;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.sql.Blob;
import Activator.Config;

public class Db {

    Connection conn = null;

    public void openDb(Config config) {
	try {
	    Class.forName(config.dbdriver);
	    conn = DriverManager.getConnection(config.dburl, config.dbuser, config.dbpass);
	} catch (Exception e) {
	    throw new java.lang.IllegalArgumentException("Can't open database connection " + e);
	}
    }

    public void closeDb() {
	try {
	    conn.close();
	} catch (Exception e) {
	    throw new java.lang.IllegalArgumentException("Can't close database connection " + e);
	}
    }

    public List<String> getRoles(String username, Config config) {
	ResultSet rs = null;
	PreparedStatement pst = null;

	List<String>roles = new ArrayList<String>();

	try {
	    pst = conn.prepareStatement(config.csrolequery);
	    pst.setString(1,username);
	    rs = pst.executeQuery();

	    while (rs.next()) {
		String role = rs.getString(1);
		roles.add(role);
	    }

	} catch (Throwable t ) {
	    throw new java.lang.IllegalArgumentException("Error in fetching roles " + t);
	} finally {
	    if(rs != null)
		try {rs.close();} catch (Exception ignore) {}
	    if(pst != null)
		try {pst.close();} catch (Exception ignore) {}
	}

	return roles;

    }

    public String findEtherForIf(Integer ifid, Config config) {
	ResultSet rs = null;
	PreparedStatement pst = null;

	String ether = null;

	try {
	    pst = conn.prepareStatement("select hw_address from netmanager.hardware_interfaces where interface_id = ?");
	    pst.setInt(1,ifid);
	    rs = pst.executeQuery();

	    if (rs.next()) {
		ether = rs.getString(1);
		if (rs.next()) {
		    throw new java.lang.IllegalArgumentException("Two entries in inventory database with the same interface ID " + ifid);
		}
	    }

	} catch (Throwable t ) {
	    throw new java.lang.IllegalArgumentException("Error in fetching ethernet address " + t);
	} finally {
	    if(rs != null)
		try {rs.close();} catch (Exception ignore) {}
	    if(pst != null)
		try {pst.close();} catch (Exception ignore) {}
	}

	return ether;

    }

    public static void main( String[] argarray) {

	Config config = new Config();
	try {
	    config.loadConfig();
	} catch (Exception e) {
	    System.out.println("error loading config file " + e);
	}

	Db db = new Db();
	if (config.csroleattr != null)
	    db.openDb(config);


    }

}
