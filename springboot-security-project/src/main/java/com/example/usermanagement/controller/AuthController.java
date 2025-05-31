package com.example.usermanagement.controller;

import com.example.usermanagement.entity.User;
import com.example.usermanagement.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;


import java.util.Set;

@RestController
public class AuthController {

    @Autowired
    private UserRepository repo;

    @Autowired
    private PasswordEncoder encoder;

   @PostMapping("/register")
public ResponseEntity<Map<String, String>> registerUser(@RequestBody User user) {
    Map<String, String> response = new HashMap<>();
    try {
        System.out.println("Registering user: " + user.getUsername());

        user.setPassword(encoder.encode(user.getPassword()));
        user.setRoles(Set.of("USER"));

        repo.save(user);
        response.put("message", "User registered successfully!");
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    } catch (Exception e) {
        e.printStackTrace();  // Print full stack trace
        response.put("error", "Registration failed: " + e.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}


    @GetMapping("/welcome")
    public String welcome() {
        return "Welcome!";
    }
}