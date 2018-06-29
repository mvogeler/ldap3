package com.example.ldap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {
    private static Logger log = LoggerFactory.getLogger(HomeController.class);

    @GetMapping("/")
    public String index() {
        return "Welcome to the home page!";
    }

    @GetMapping("/chemists")
    public String chemists(){
        return "Hello chemists";
    }

    @GetMapping("/mathematicians")
    public String mathematicians(){
        return "Hello mathematicians";
    }
}
