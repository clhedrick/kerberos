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
