package com.example.usermanagement;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SpringBootSecurityApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringBootSecurityApplication.class, args);
    }
}


// To Run the project 

// ./mvnw clean install
// mvn spring-boot:run


// Register user.
// http://localhost:8080/register

// Open Browser and login with your resistered credentials
// http://localhost:8080/login

// GET http://localhost:8080/welcome
// You should see = Wlecome!



