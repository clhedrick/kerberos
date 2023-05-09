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
import org.springframework.security.config.Customizer;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.config.ldap.LdapBindAuthenticationManagerFactory;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.context.annotation.Bean;
import Activator.Config;

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

@Configuration
public class SpringSecurityConfig {

    // new style lambda version, so it will survive
    // newer versions of Spring
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	http
	    // jee means to pass on the remote_user attribute from apache
	    // tomcat server.xml must also have
	    //  tomcatAuthentication="false"
	    // in the ajp connector
	    // authenticated user will show up as request.getRemoteUser()
	    // for mod_auth_gssapi it will be the kerberos principal
	    .jee(Customizer.withDefaults())
	    .httpBasic(Customizer.withDefaults())
	    .authorizeHttpRequests(authorize->authorize
	    // ldap user auth for request is optional
	    // it's only used for /enrollhosts, but
	    // it's more complex to do it just for that
	    // than to recognize it anywhere. Of course
	    // the code won't pay attention to it anywhere else
	      .requestMatchers("/enrollhosts").permitAll()
              .requestMatchers("/**").permitAll())
	    // need to disable CSRF for DELETE to work
	    .csrf(csrf->csrf
	      .ignoringRequestMatchers("/enrollhosts/**")
	      .ignoringRequestMatchers("/groups/login"));
	
	return http.build();
    }

    // usual documentation says to use AuthenticationManagerBuilder,
    // but that is being deprecated. I trust this will continue
    // to work.
    @Bean
    public LdapContextSource getContextSource() {
    	  LdapContextSource contextSource = new LdapContextSource();

	  // note that the URL can be ldaps://server1, ldap2://server2
	  // so need to change , to space. Suffix here doesn't seem to work
	  var url = Config.getConfig().kerbldapurl.trim().replaceAll("[ ,]+", " ");

	  var logger = LogManager.getLogger();
	  System.out.println("ldap URL for Spring security: " + url);

	  contextSource.setUrl(url);
	  // may not be needed within Spring Security
	  contextSource.afterPropertiesSet(); //needed otherwise you will have a NullPointerException in spring

	  return contextSource;
    }


    @Bean
    AuthenticationManager ldapAuthenticationManager(
            BaseLdapPathContextSource contextSource) {

        LdapBindAuthenticationManagerFactory factory = 
            new LdapBindAuthenticationManagerFactory(contextSource);
        factory.setUserDnPatterns("uid={0}" + Config.getConfig().usersuffix.trim());
        return factory.createAuthenticationManager();
    }

}
