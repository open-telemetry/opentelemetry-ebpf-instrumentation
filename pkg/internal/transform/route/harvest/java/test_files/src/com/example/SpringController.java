package com.example;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping({"/api/", "/v1"})
public class SpringController {
    @GetMapping("/users/{id:\\d+}/")
    public String user() {
        return "";
    }

    @PostMapping(path = {"/orders", "/orders/{orderId}"})
    public String orders() {
        return "";
    }

    @GetMapping
    public String root() {
        return "";
    }

    @GetMapping("/assets/*")
    public String wildcard() {
        return "";
    }

    @GetMapping("${api.base}/dynamic")
    public String dynamic() {
        return "";
    }
}
