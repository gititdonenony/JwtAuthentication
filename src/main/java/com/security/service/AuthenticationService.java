package com.security.service;

import com.security.auth.AuthenticationRequest;
import com.security.auth.AuthenticationResponse;
import com.security.config.JwtUtils;
import com.security.model.RegisterRequest;
import com.security.model.User;
import com.security.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    // Constructor injection
    public AuthenticationService(UserRepository userRepository, JwtUtils jwtUtils, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    // Mapping from RegisterRequest to User
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        // Create a new user object using the data from the RegisterRequest
        var user = User.builder()
                // Set the user's attributes from the RegisterRequest's properties
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                // We need to encode the password before saving it to the database
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();
        // Save the user to the database
        var savedUser = userRepository.save(user);
        // Generate the JWT token
        String jwtToken = jwtUtils.generateToken(user);
        // Return the JWT token to the client
        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // First step: Authenticate the user using authenticationManager
        // Second step: Authenticate the user's credentials using the provided email and password
        // Third step: Retrieve the user from the database using the UserRepository
        // Fourth step: Generate a JWT token using the JwtUtils
        // Fifth step: Return the JWT token to the client
        // In this case, we're using a UsernamePasswordAuthenticationToken and authenticating it
        // using the authenticationManager. If the authentication is successful, we retrieve the user
        // from the database and generate a JWT token. If the authentication fails, an exception
        // will be thrown.
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        String jwtToken = jwtUtils.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();

    }
}
