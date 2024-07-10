package com.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.model.RegisterRequest;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AdminController {
    private final AuthenticationService authenticationService; 
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterRequest registerRequest){
        AuthneticationResponse authenticationResponse = AuthenticationService.register(registerRequest);
        return ResponseEntity.ok(authenticationResponse);
    }

}
