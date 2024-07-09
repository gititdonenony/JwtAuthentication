package com.security.auth;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    private final AuthenticationService authenticationService;

    public AuthenticationController(AuthenticationService authenticationService) {
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest registerRequest
    ) {
        AuthenticationResponse authResponse = authenticationService.register(registerRequest);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        return ResponseEntity.ok(authenticationService.authenticate(request));
    }
}

//The @RestController annotation indicates that this class is a controller in a Spring Boot application. It's responsible for handling HTTP requests and returning responses.
//The @RequestMapping("/api/auth") annotation specifies the base URL path for all the methods in this class. In this case, the base URL path is /api/auth.
//The AuthenticationController class has a private field authenticationService of type AuthenticationService. This field is initialized in the constructor using dependency injection. Dependency injection is a design pattern that allows the dependencies of a class to be provided externally, rather than being created within the class itself.
//The register method is annotated with @PostMapping("/register"). This indicates that this method will handle HTTP POST requests with the URL path /api/auth/register. The method takes a RegisterRequest object as a parameter, which contains the necessary information for user registration. It then calls the register method of the authenticationService and returns the response as a JSON object using ResponseEntity.ok(authResponse).
//The authenticate method is annotated with @PostMapping("/authenticate"). This indicates that this method will handle HTTP POST requests with the URL path /api/auth/authenticate. The method takes an AuthenticationRequest object as a parameter, which contains the necessary information for user authentication. It then calls the authenticate method of the authenticationService and returns the response as a JSON object using ResponseEntity.ok(authenticationService.authenticate(request)).
// In summary, the AuthenticationController class is responsible for handling user registration and authentication requests in a Spring Boot application. It uses dependency injection to inject the AuthenticationService and handles HTTP POST requests to the /api/auth/register and /api/auth/authenticate endpoints. The responses are returned as JSON objects using ResponseEntity.ok().