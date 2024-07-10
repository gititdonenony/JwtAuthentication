package com.security.config;

import com.security.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class ApplicationConfig {
    private final UserRepository userRepository;

    public ApplicationConfig(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        //
        authProvider.setUserDetailsService(userDetailsService());
        // Encoding the password for authentication
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

}


//@Configuration: This annotation indicates that the class declares one or more @Bean methods.
// These methods are used to create and configure Spring Beans.
//private final UserRepository;: This line declares a private final field userRepository of
// type UserRepository. The UserRepository interface is assumed to be a custom interface that
// extends JpaRepository or another relevant interface for interacting with the user data in
// the database.
//public ApplicationConfig(UserRepository userRepository): This is the constructor of the
//ApplicationConfig class. It takes an instance of UserRepository as a parameter and
// initializes the userRepository field.
//@Bean: This annotation is used to define a Spring Bean.
//public PasswordEncoder passwordEncoder(): This method creates and returns a PasswordEncoder
// bean. In this case, it uses BCryptPasswordEncoder to encode passwords.
//public UserDetailsService userDetailsService(): This method creates and returns a
// UserDetailsService bean. The UserDetailsService is responsible for retrieving user-related
// data based on the provided username. In this case, it uses a lambda expression to fetch
// the user from the database using the UserRepository and throws a UsernameNotFoundException
// if the user is not found.
//public AuthenticationProvider authenticationProvider(): This method creates and returns an
// AuthenticationProvider bean. The DaoAuthenticationProvider is a built-in authentication
// provider in Spring Security that uses a UserDetailsService to authenticate users.
// In this case, it sets the UserDetailsService and PasswordEncoder created earlier.
//public AuthenticationManager(AuthenticationConfiguration config) throws Exception:
// This method creates and returns an AuthenticationManager bean.
// The AuthenticationConfiguration bean provides the default authentication manager.
// In this case, it simply returns the default authentication manager obtained from the
// AuthenticationConfiguration.
//Overall, this code snippet configures essential components for user authentication and
// authorization in a Spring Boot application. The PasswordEncoder, UserDetailsService,
// AuthenticationProvider, and AuthenticationManager beans are created and configured using
// the @Bean annotation. This configuration ensures that Spring Security can securely
// authenticate users and protect the application's resources.
