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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import Activator.User;
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
	if (username.equals("hedrick"))
	    username = "dsmith";

	// set up model for JSTL
	// User.doUser calls the actual activator code to find out which clusters the user
	// is on and can activate on
	
	model.addAttribute("ok", User.doUser(username, clusters, currentClusters, ineligibleClusters, null, false, false, true));
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
	if (username.equals("hedrick"))
	    username = "dsmith";
	
	boolean ok = User.doUser(username, null, null, null, cluster, false, false, true);
	if (ok && utils.needsPassword(username)) {
	    try {
		response.sendRedirect("../changepass/changepass?cluster=" + URLEncoder.encode(cluster));
	    } catch (Exception e) {}
	}

	if (!ok)
	    model.addAttribute("activatefailed", true);

	return activateGet(request, response, model);

    }

}
