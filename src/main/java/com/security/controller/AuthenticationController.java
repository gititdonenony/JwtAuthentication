package com.security.controller;

import com.security.auth.AuthenticationRequest;
import com.security.auth.AuthenticationResponse;
import com.security.service.AuthenticationService;
import com.security.model.RegisterRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    // Dependency injection
    private final AuthenticationService authenticationService;

    // Constructor injection
    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    //Mapping from RegisterRequest to User
    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest) {
        // Call the register method of the authenticationService
        AuthenticationResponse authResponse = authenticationService.register(registerRequest);
        // Return the response
        return ResponseEntity.ok(authResponse);
    }

    // Mapping from AuthenticationRequest to AuthenticationResponse
    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        // Call the authenticate method of the authenticationService
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}