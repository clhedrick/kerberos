package application;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    // We're doing our own authentiction. So we essentially disable 
    // Spring's by saying everything is authorized. The reason we want
    // Spring security is because it handles CSRF for us as long as
    // we use Thyme forms.
     @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
	    .authorizeRequests()
	    .antMatchers("/**").permitAll();
    }

}
