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
    // we use Thyme forms.
     @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
	    .httpBasic().and().authorizeRequests()
	    // use basic auth with LDAP for this one URL only
            .antMatchers("/enrollhosts").authenticated()
	    .antMatchers("/**").permitAll();
    }

    // when basic auth is used, this specifies what it is; LDAP in this case
    @Override
    public void configure(AuthenticationManagerBuilder auth) throws Exception {

	auth
	    .ldapAuthentication()
	    .contextSource()
	    // this should work, and does with ldap, but not ldaps
	    //	    .url("ldaps:///dc=cs,dc=rutgers,dc=edu")
	    // for some reason a base has to be specified. 
	    .url(Config.getConfig().kerbldapurl + "/" + Config.getConfig().usersuffix.substring(1))
	    .and()
	    .userDnPatterns("uid={0}");

    }

}
