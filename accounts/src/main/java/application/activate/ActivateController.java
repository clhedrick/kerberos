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

package application;

import java.util.List;
import java.util.ArrayList;
import java.util.Date;
import java.net.URLEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.format.annotation.DateTimeFormat;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import Activator.User;
import Activator.Uid;
import common.utils;


@Controller
public class ActivateController {

    public String filtername(String s) {
	if (s == null)
	    return null;
	String ret = s.replaceAll("[^-_.a-z0-9]","");
	if (ret.equals(""))
	    return null;
	return ret;
    }

    @GetMapping("/activate/activate")
    public String activateGet(HttpServletRequest request, HttpServletResponse response, Model model) {
	List<String> clusters = new ArrayList<String>();	    
	List<String> currentClusters = new ArrayList<String>();	    
	List<String> ineligibleClusters = new ArrayList<String>();	    
	String username = request.getRemoteUser();
	username = Uid.localUid(username, Activator.Config.getConfig());

	// set up model for JSTL
	// User.doUser calls the actual activator code to find out which clusters the user
	// is on and can activate on
	
	model.addAttribute("username", username);
	if (username != null)
	    model.addAttribute("ok", User.doUser(username, clusters, currentClusters, ineligibleClusters, null, false, false, false, true));
	else 
	    model.addAttribute("ok", false);
	model.addAttribute("clusters", clusters);
	model.addAttribute("currentClusters", currentClusters);
	model.addAttribute("ineligibleClusters", ineligibleClusters);
	model.addAttribute("helpmail", Activator.Config.getConfig().helpmail);

        return "activate/activate";
    }

    @PostMapping("/activate/activate")
    public String activateSubmit(@RequestParam(value="cluster", required=false) String cluster,
				 HttpServletRequest request, HttpServletResponse response,
				 Model model) {
	cluster = filtername(cluster);
	
	String username = request.getRemoteUser();
	username = Uid.localUid(username, Activator.Config.getConfig());
	
	boolean ok = User.doUser(username, null, null, null, cluster, false, false, false, true);
	if (ok && utils.needsPassword(username)) {
	    try {
		response.sendRedirect("../changepass/changepass?cluster=" + URLEncoder.encode(cluster, "UTF-8"));
	    } catch (Exception e) {}
	}

	if (!ok)
	    model.addAttribute("activatefailed", true);

	return activateGet(request, response, model);

    }

}
