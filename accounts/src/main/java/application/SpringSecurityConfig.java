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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.access.AccessDeniedHandler;
import Activator.Config;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    // We're doing our own authentiction. So we essentially disable 
    // Spring's by saying everything is authorized. The reason we want
    // Spring security is because it handles CSRF for us as long as
    // we use Thyme forms, and also to handle BASIC.
    //   Note that http BASIC auth is enabled.
    // However nothing says authentication required, which makes it
    // optional. The hosts enrollment process uses BASIC auth, but
    // some functions don't require it. So the code checks whether
    // the request is authenticated or not.
    //   In this configuration there's actually nothing accomplished
    // by listing /enrollhosts separately. It used to have a different
    // requirement.

    // The second configure sets up the LDAP authentication used
    // to implement the HTTP BASIC.

     @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
	    .httpBasic().and().authorizeRequests()
	    // ldap user auth for request is optional
	    // it's only used for /enrollhosts, but
	    // it's more complex to do it just for that
	    // than to recognize it anywhere. Of course
	    // the code won't pay attention to it anywhere else
            .antMatchers("/enrollhosts").permitAll()
	    .antMatchers("/**").permitAll()
	    // need to disable CSRF for DELETE to work
	    .and()
	    .csrf().ignoringAntMatchers("/enrollhosts/**");
    }

    // when basic auth is used, this specifies what it is; LDAP in this case
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
	// in config file, suffix starts with comma
	var suffix = "/" + Config.getConfig().usersuffix.trim().substring(1);

	// for some reason a base has to be specified with ldaps.
	// note that the URL can be ldaps://server1, ldap2://server2, so need
	// to add base to each of them. allow space and comma separation in config file
	// the syntax here is just space
	var url = Config.getConfig().kerbldapurl.trim().replaceAll("[ ,]+", suffix + " ") + suffix;

	var logger = LogManager.getLogger();
	System.out.println("ldap URL for Spring security: " + url);

	auth
	    .ldapAuthentication()
	    .contextSource()
	    .url(url)
	    .and()
	    .userDnPatterns("uid={0}");
    }

}
