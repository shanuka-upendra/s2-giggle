package com.security.controller;


import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/secure")
@RequiredArgsConstructor
public class AuthController {

    @GetMapping("/user")
    public String sayHelloToUser() {
        return "Hello User!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String sayHelloToAdmin() {
        return "Hello Admin!";
    }

    @GetMapping("/manager")
    public String sayHelloToManager() {
        return "Hello Manager!";
    }

    @GetMapping("/staff")
    public String sayHelloToStaff() {
        return "Hello Staff!";
    }


}
