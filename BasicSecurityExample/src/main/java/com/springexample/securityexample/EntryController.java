package com.springexample.securityexample;

import com.springexample.securityexample.jwt.JwtUtils;
import com.springexample.securityexample.jwt.LoginRequest;
import com.springexample.securityexample.jwt.LoginResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
public class EntryController {

    // The following fields are needed for use with JWT authentication.
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtUtils jwtUtils;


    // This endpoint is publicly accessible and does not require authentication. Unless
    // you have configured security to require authentication for all endpoints, or
    // you are using default security settings that require authentication for all requests.
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


    // This endpoint is used to authenticate a user and generate a JWT token.
    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager.authenticate(
                  new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                  )
            );
        } catch (AuthenticationException e) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwt = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles =
              userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList();

        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwt);
        return ResponseEntity.ok(response);
    }
}
