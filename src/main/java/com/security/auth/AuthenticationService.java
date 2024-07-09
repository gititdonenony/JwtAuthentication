package com.security.auth;

import com.security.config.JwtService;
import com.security.model.User;
import com.security.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthenticationService(UserRepository userRepository, JwtService jwtService, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    // Mapping from RegisterRequest to User
    public AuthenticationResponse register(RegisterRequest registerRequest) {
        var user = User.builder()
                .firstName(registerRequest.getFirstName())
                .lastName(registerRequest.getLastName())
                .email(registerRequest.getEmail())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())
                .build();
        var savedUser = userRepository.save(user);
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //FirstStep
        //We need to validate our request (validate whether password & username is correct)
        //Verify whether user present in the database
        //Which AuthenticationProvider -> DaoAuthenticationProvider (Inject)
        //We need to authenticate using authenticationManager injecting this authenticationProvider
        //SecondStep
        //Verify whether userName and password is correct => UserNamePasswordAuthenticationToken
        //Verify whether user present in db
        //generateToken
        //Return the token
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        var user = userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        String jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).build();

    }
}

//The AuthenticationService class has two main methods:
//register(RegisterRequest registerRequest): This method handles user registration.
// It takes a RegisterRequest object as input, maps it to a User object, encodes the password
// using the PasswordEncoder, saves the user to the database using the UserRepository,
// generates a JWT token using the JwtService, and returns an AuthenticationResponse object
// containing the JWT token.
//authenticate(AuthenticationRequest request): This method handles user authentication.
// It takes an AuthenticationRequest object as input, validates the user's credentials,
// verifies whether the user exists in the database, authenticates the user using the
// AuthenticationManager, generates a JWT token using the JwtService, and returns an
// AuthenticationResponse object containing the JWT token.
//In the authenticate method, the code first authenticates the user using the
// AuthenticationManager by creating a UsernamePasswordAuthenticationToken with the provided
// email and password. Then, it retrieves the user from the database using the UserRepository
// and generates a JWT token using the JwtService. Finally, it returns an AuthenticationResponse
// object containing the JWT token.
//Overall, the AuthenticationService class provides a secure and efficient way to handle user
// authentication and registration in a Spring Boot application.

