package com.springexample.securityexample;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    /**
     * Removing default form login will remove the login page and will not give us access to the
     * logout functionality (/logout endpoint). We can still use HTTP Basic authentication,
     * instead of an HTML form for login, we see a browser prompt/popup for username and password.
     * <p>
     * Basic security sends Basic Authorization header (base64 encoded username:password) with each
     * request, and we'll notice a JSESSIONID request cookie in the browser, which is used to maintain
     * the session state.
     * <p>
     * Form login also sends a Basic Authorization header with each request, and both a request and
     * response cookie for JSESSIONID, which is used to maintain the session state.
     */

    // The default security configuration for a Spring Boot application is shown in
    // SpringBootWebSecurityConfiguration.java. By default it provides form-based login and
    // HTTP Basic authentication. The default user is 'user' with a password that is generated
    // and printed in the console. The default user and password can be overridden in the
    // application.properties file. 

    @Bean
    SecurityFilterChain basicSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        //http.formLogin(withDefaults());

        // (Optional) The following line makes the application stateless by disabling session
        // management, no more cookies.
        http.sessionManagement(session ->
              session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.httpBasic(withDefaults());
        return http.build();
    }

    // (Optional) To add in-memory authentication and handle multiple users, then we need to define the
    // following bean. This is mainly for demonstration purposes, not recommended for production use.
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
              .password("{noop}password1") // {noop} indicates no password encoder is used
              .roles("USER")
              .build();

        UserDetails admin = User.withUsername("admin")
              .password("{noop}adminPass") // {noop} indicates no password encoder is used
              .roles("ADMIN")
              .build();

        return new InMemoryUserDetailsManager();
    }
}
