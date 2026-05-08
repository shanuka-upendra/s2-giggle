package com.security.controller;


import com.security.model.User;
import com.security.service.MyUserDetailService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/secure")
@RequiredArgsConstructor
public class AuthController {

    private static final Set<String> ALLOWED_ROLES = Set.of("USER", "STAFF", "MANAGER", "ADMIN");
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
    public ResponseEntity<Map<String, Object>> registerUser(@RequestBody User user) {
        if (user.getUsername() == null || user.getUsername().trim().isEmpty()) {
            return buildErrorResponse("Username is required", HttpStatus.BAD_REQUEST);
        }
        if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
            return buildErrorResponse("Password is required", HttpStatus.BAD_REQUEST);
        }
        if (user.getRole() == null || user.getRole().trim().isEmpty()) {
            return buildErrorResponse("Role is required (USER, STAFF, MANAGER, ADMIN)", HttpStatus.BAD_REQUEST);
        }

        String normalizedRole = user.getRole().trim().toUpperCase();
        if (!ALLOWED_ROLES.contains(normalizedRole)) {
            return buildErrorResponse("Invalid role. Allowed roles: USER, STAFF, MANAGER, ADMIN", HttpStatus.BAD_REQUEST);
        }

        user.setUsername(user.getUsername().trim());
        user.setRole(normalizedRole);
        userService.registerUser(user);
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "User registered successfully");
        response.put("data", Map.of("username", user.getUsername(), "role", user.getRole()));
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    private ResponseEntity<Map<String, Object>> buildErrorResponse(String message, HttpStatus status) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "error");
        response.put("message", message);
        return ResponseEntity.status(status).body(response);
    }

}
