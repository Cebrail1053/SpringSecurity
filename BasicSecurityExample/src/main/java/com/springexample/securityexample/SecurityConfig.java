package com.springexample.securityexample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    private DataSource dataSource;

    /**
     * The default security configuration for a Spring Boot application is shown in
     * SpringBootWebSecurityConfiguration.java. By default, it provides form-based login and
     * HTTP Basic authentication. The default user is 'user' with a password that is generated
     * and printed in the console. The default user and password can be overridden in the
     * application.properties file.
     * <p>
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
        // Disable CSRF for H2 console as it prevents the H2 console from working properly.
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
        // Enable H2 console support, which is a web-based database console for H2.
        http.headers(headers -> headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin));

        http.authorizeHttpRequests((requests) ->
              requests
                    .requestMatchers("/h2-console/**").permitAll()
                    .anyRequest().authenticated());
        //        http.formLogin(withDefaults()); // Uncomment this line to enable form-based login

        // (Optional) The following line makes the application stateless by disabling session
        // management, no more cookies.
        http.sessionManagement(session ->
              session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.httpBasic(withDefaults());
        return http.build();
    }

    // (Optional) To add in-memory authentication or database authentication, and handle multiple users,
    // then we need to define the following bean.
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user1 = User.withUsername("user1")
              .password("{noop}password1") // {noop} indicates no password encoder is used
              .roles("USER")
              .build();

        UserDetails admin = User.withUsername("admin")
              .password(passwordEncoder().encode("adminPass")) // Uses BCryptPasswordEncoder
              .roles("ADMIN")
              .build();

        // Uncomment the following line to use in-memory user details manager. This is mainly for
        // demonstration purposes, not recommended for production use
//        return new InMemoryUserDetailsManager(user1, admin);

        // Use JdbcUserDetailsManager to manage users in a database. Ensure you have a DataSource bean
        // configured in your application.
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
