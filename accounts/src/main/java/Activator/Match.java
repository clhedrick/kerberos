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
import java.util.regex.Pattern;

// ldap filter, sort of
// matches are always case-independent
// with ~ operator the pattern is a Java regexp

public class Match {
    static HashMap<String, ArrayList<String>> data = new HashMap<String, ArrayList<String>>();
    static {
	ArrayList<String> values = new ArrayList<String>();
	values.add("faculty");
	values.add("student");
	data.put("employeetype", values);
	values = new ArrayList<String>();
	values.add("10325");
	data.put("rulinkRutgersEduOrganizationCode", values);
	values = new ArrayList<String>();
	values.add("2017:7:01:198:311:01");
	data.put("rulinkRutgersEduStudentCourseReg", values);
    }

    // takes a string with *'s in it and turns it into a regexp. 
    // turn * into .* and quote the rest
    static String makepattern(String target) {
	String pattern = "";
	target = target.toLowerCase();
	while (target.length() > 0) {
	    int i = target.indexOf('*');
	    if (i < 0) {
		pattern = pattern + Pattern.quote(target);
		target = "";
	    } else if (i > 0) {
		pattern = pattern + Pattern.quote(target.substring(0, i));
		pattern = pattern + ".*";
		target = target.substring(i+1);
	    } else {
		pattern = pattern + ".*";
		target = target.substring(1);
	    }			
	}
	return pattern;
    }

    static boolean matchLdap(Map<String, List<String>> attributes, String filter) {
	return matchLdap(attributes, filter, filter);
    }

    // given a map that contains values of all the attributes, and a filter
    // check whether the filter matches
    static boolean matchLdap(Map<String, List<String>> attributes, String filter, String wholefilter) {
	// check syntax of filter
	filter = filter.trim();
	if (filter.charAt(0) != '(')
	    throw new java.lang.IllegalArgumentException("filter must begin with (, bad filter: " + wholefilter);
	if (filter.charAt(filter.length() - 1) != ')')
	    throw new java.lang.IllegalArgumentException("filter must end with (, bad filter: " + wholefilter);
	// remove surrounding ()
	filter = filter.substring(1, filter.length()-1);
	filter = filter.trim();
	char op = filter.charAt(0);

	// prefix operators
	if (op == '&' || op == '|' || op == '!') {

	    // use common code for anything with subexpressions
	    filter = filter.substring(1);

	    // build list of subexpressions
	    List <String>exprs = new ArrayList<String>();
	    while (filter.length() > 0) {
		filter=filter.trim();
		if (filter.charAt(0) != '(') {
		    throw new java.lang.IllegalArgumentException("expression must begin with (, bad fiter: " + wholefilter);
		}
		// end is harder. need a ) that matches the (
		// but there may be subexpressions. So we have to check every
		// ( and ), and keep track of the level. Only stop when we
		// reach ) at the outer level.
		int level = 1;
		int i = 1;
		for (; i < filter.length(); i++) {
		    if (filter.charAt(i) == '(')
			level++;
		    else if (filter.charAt(i) == ')') {
			level--;
			if (level == 0)
			    break;
		    }
		}
		if (level != 0)
		    throw new java.lang.IllegalArgumentException("expression must end with ), bad filter: " + wholefilter);
		exprs.add(filter.substring(0, i+1));
		filter = filter.substring(i+1);
	    }

	    // now execute the operation
	    if (op == '&') {
		for (String expr: exprs) {
		    if (!matchLdap(attributes, expr, wholefilter))
			return false;
		}
		return true;
	    } else if (op == '|') {
		for (String expr: exprs) {
		    if (matchLdap(attributes, expr, wholefilter))
			return true;
		}
		return false;
	    } else if (op == '!') {
		if (exprs.size() != 1)
		    throw new java.lang.IllegalArgumentException("! must be followed by a single expression, bad filter: " + wholefilter);		    
		return ! matchLdap(attributes, exprs.get(0), wholefilter);
	    }

	}

	// relational operators
	if (filter.indexOf('(') >= 0 || filter.indexOf(')') >= 0)
	    throw new java.lang.IllegalArgumentException("filter expression contains ( or ), bad filter: " + wholefilter);				  
	filter = filter.trim();

	// seems legal. Interpret = and ~ operator
	int equal = filter.indexOf('=');
	int tilde = filter.indexOf('~');
	if (equal <= 0 && tilde <= 0) 
	    throw new java.lang.IllegalArgumentException("filter expression must contain =, bad filter: " + wholefilter);				  

	// interpret ~, it's a java regexp
	if (tilde > 0 && (equal <= 0 || tilde < equal)) {
	    // tilde is first or only operator
	    String target = filter.substring(tilde+1);
	    target = target.trim();
	    List<String>values = attributes.get(filter.substring(0, tilde).toLowerCase().trim());
	    if (values == null)
		return false;
	    for (String value: values) {
		if (value.toLowerCase().matches(target.toLowerCase()))
		    return true;
	    }
	    return false;
	}
	
	// now has to be some kind of =
	// check for !=, <=, >=
	boolean not = false;
	boolean compare = false;
	boolean less = false;
	if (filter.charAt(equal-1) == '!')
	    not = true;
	if (filter.charAt(equal-1) == '<' || filter.charAt(equal-1) == '>') {
	    compare = true;
	    less = (filter.charAt(equal-1) == '<');
	}

	// execute the test
	List<String>values = attributes.get(filter.substring(0, equal - ((not||compare)?1:0)).toLowerCase().trim());
	if (values == null)
	    return not;
	String target = filter.substring(equal+1);
	target = target.trim();

	// <= and >=
	if (compare) {
	    for (String value: values) {
		int compareto = value.compareToIgnoreCase(target);
		if (less) {
		    if (compareto <= 0)
			return true;
		} else {
		    if (compareto >= 0)
			return true;
		}
	    }
	    return false;
	}

	// = and != each have 3 subcases, 
	//    *, i.e. the whole target is *
	//    target has a * in it e.g. abc*def
	//    normal

	// !=

	if (not) {
	    if ("*".equals(target))
		return !(values.size() > 0);
	    String [] targets = target.split("\\|");
	    for (String value: values) {
		for (int i = 0; i < targets.length; i++) {
		    String t = targets[i].trim();
		    if (t.indexOf('*') >= 0) {
			String pattern = makepattern(t.toLowerCase());
			if (value.toLowerCase().matches(pattern))
			    return false;
		    } else if (value.equalsIgnoreCase(t))
			return false;
		}
	    }
	    return true;
	} else {
        // =
	    if ("*".equals(target))
		return values.size() > 0;
	    String [] targets = target.split("\\|");
	    for (String value: values) {
		for (int i = 0; i < targets.length; i++) {
		    String t = targets[i].trim();
		    if (t.indexOf('*') >= 0) {
			String pattern = makepattern(t.toLowerCase());
			if (value.toLowerCase().matches(pattern))
			    return true;
		    } else if (value.equalsIgnoreCase(t))
			return true;
		}
	    }
	    return false;
	}
    }

    // 2017:7:01:198:311:01
    public static String makeclass (String c, Config config) {
	String [] parts = c.split(":");
	if (parts.length < 5)
	    return c;

	String dept = null;
	if (config.departments != null) {
	    for (Config.Rule rule: config.departments.rules) {
		if (c.matches(rule.filter)) {
		    dept = rule.groupName;
		}
	    }
	}
	if (dept == null)
	    dept = "dept" + parts[3] + "-";

	String term = parts[1];
	if ("0".equals(term))
	    term = "w";
	else if ("1".equals(term))
	    term = "s";
	else if ("7".equals(term))
	    term = "u";
	else if ("9".equals(term))
	    term = "f";
	else
	    term = "-" + term + "-";

	String year = parts[0];
	if (year.startsWith("20"))
	    year = year.substring(2);

	return dept + parts[4] + term + year;

    }

    public static void main( String[] args) {
	Config config = new Config();
	try {
	    config.loadConfig();
	} catch (Exception e) {
	    System.out.println("error " + e);
	}

	System.out.println(makeclass(args[0], config));
	//	System.out.println(matchLdap(data, args[0]));
    }
}
