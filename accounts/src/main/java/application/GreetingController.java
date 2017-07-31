package application;

import java.util.List;
import java.util.Date;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.format.annotation.DateTimeFormat;

@Controller
public class GreetingController {

    @GetMapping("/greeting")
    public String greeting(@RequestParam(value="name", required=false, defaultValue="World") String name, Model model) {
        model.addAttribute("name", name);
        return "greeting";
    }

    @PostMapping("/greeting")
    public String greetingSubmit(@RequestParam(value="host", required=false) List<String>host,@RequestParam(value="clist", required=false) List<String>clist, @RequestParam(value="d",defaultValue="01/01/2001")  @DateTimeFormat(pattern="MM/dd/yyyy") Date d) {
	System.out.println(host);
	System.out.println(clist);
	System.out.println(d);
        return "greeting";
    }

    @ExceptionHandler(org.springframework.core.convert.ConversionFailedException.class)
    public String greetingException(org.springframework.core.convert.ConversionFailedException e) {
	System.out.println("error");
	return "greeting";
    }

}
