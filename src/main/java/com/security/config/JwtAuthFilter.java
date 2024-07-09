package com.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal
            (@NonNull HttpServletRequest request,
             @NonNull HttpServletResponse response,
             @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        //Verify whether request has Authorization header and it has Bearer in it
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String email;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        //Extract jwt from the Authorization
        jwt = authHeader.substring(7);
        //Verify whether user is present in db
        //Verify whether token is valid
        email = jwtService.extractUsername(jwt);
        //If user is present and no authentication object in securityContext
        if (email != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(email);
            //If valid set to security context holder
            UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            authToken.setDetails(
                    new WebAuthenticationDetailsSource().buildDetails(request)
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }
        filterChain.doFilter(request, response);
    }

    //Verify if it is whitelisted path and if yes dont do anything
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) throws ServletException {
        return request.getServletPath().contains("/crackit/v1/auth");
    }

}

//The JwtAuthFilter class extends OncePerRequestFilter, which ensures that the filter is executed only once per request.
//2.
//The JwtAuthFilter class has two private fields: jwtService and userDetailsService. These fields are injected using constructor injection, allowing the filter to access the necessary services for JWT token verification and user details retrieval.
//3.
//The doFilterInternal method is overridden to perform the actual filtering logic. This method is called for each request that passes through the filter.
//4.
//Inside the doFilterInternal method, the code first checks if the request has an Authorization header and if it starts with "Bearer ". If either condition is not met, the filter allows the request to proceed by calling filterChain.doFilter(request, response) and returning.
//        5.
//If the request has a valid Authorization header, the code extracts the JWT token from the header by removing the "Bearer " prefix.
//6.
//The code then verifies whether the user associated with the extracted JWT token exists in the database and whether the token is valid. This verification process is not shown in the provided snippet, but it would involve calling methods from the jwtService to extract the username from the JWT token and then querying the user repository to check if a user with the extracted email exists.
//7.
//If the user is present and no authentication object is already set in the security context, the code retrieves the user's details using the userDetailsService and creates a UsernamePasswordAuthenticationToken object with the user's details.
//        8.
//The authentication token is then set to the security context holder, which allows Spring Security to authenticate the user for subsequent requests.
//        9.
//Finally, the filter allows the request to proceed by calling filterChain.doFilter(request, response).
//        10.
//The shouldNotFilter method is overridden to specify paths that should be whitelisted and not require authentication. In this case, the filter checks if the request's servlet path contains "/crackit/v1/auth". If it does, the filter allows the request to proceed without authentication.
//
//
//Overall, the JwtAuthFilter class is responsible for verifying and authenticating users based on the JWT token provided in the request's Authorization header. It ensures that only authenticated users can access the application's protected resources.