package com.security.controller;


import com.security.model.User;
import com.security.service.MyUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/secure")
@RequiredArgsConstructor
public class AuthController {

    private final MyUserDetailService userService;

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

    @PostMapping("/auth/register")
    public void registerUser(@RequestBody User user) {
        userService.registerUser(user);
    }


}
