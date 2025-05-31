package com.example.usermanagement.security;


import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.*;

import java.io.IOException;
import java.util.*;

public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
        setFilterProcessesUrl("/login"); // matches your POST /login
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {

        try {
            Map<String, String> creds = new ObjectMapper().readValue(request.getInputStream(), Map.class);
            UsernamePasswordAuthenticationToken token =
                    new UsernamePasswordAuthenticationToken(creds.get("username"), creds.get("password"));
            return authenticationManager.authenticate(token);
        } catch (IOException e) {
            throw new AuthenticationServiceException("Invalid login request", e);
        }
    }

    @Override
protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                        FilterChain chain, Authentication authResult)
        throws IOException, ServletException {
    // Set authentication in the security context
    SecurityContextHolder.getContext().setAuthentication(authResult);

    response.setStatus(HttpServletResponse.SC_OK);
    response.setContentType("application/json");
    response.getWriter().write("{\"message\": \"Login successful\"}");
    response.getWriter().flush();
}


    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed)
            throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write("{\"error\": \"Login failed: " + failed.getMessage() + "\"}");
        response.getWriter().flush();
    }
}
