package com.springexample.securityexample;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
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

    @Bean
    SecurityFilterChain basicSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests.anyRequest().authenticated());
        //http.formLogin(withDefaults());

        // The following line makes the application stateless by disabling session management, no more cookies.
        http.sessionManagement(session ->
              session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.httpBasic(withDefaults());
        return http.build();
    }
}
