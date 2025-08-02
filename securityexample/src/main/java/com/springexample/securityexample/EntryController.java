package com.springexample.securityexample;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class EntryController {

    @GetMapping("/hello")
    public String index() {
        return "Welcome to the Spring Security Example!";
    }
}
