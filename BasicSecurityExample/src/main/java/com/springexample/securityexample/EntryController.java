package com.springexample.securityexample;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EntryController {

    @GetMapping("/hello")
    public String index() {
        return "Welcome to the Spring Security Example!";
    }

    // The following endpoints leverage method-level security annotations
    // to restrict access based on user roles. SecurityConfig must enable
    // method security for this to work properly.

    // PreAuthorize checks if the user has the 'USER' role before accessing the endpoint.
    // PostAuthorize checks the user's role after the method execution.
    @GetMapping("/user")
    @PreAuthorize("hasRole('USER')")
    public String userEndpoint() {
        return "Hello, User!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminEndpoint() {
        return "Hello, Admin!";
    }
}
