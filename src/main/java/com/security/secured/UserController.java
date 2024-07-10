package com.security.secured;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth/user")
public class UserController {
    @GetMapping
    public String getUser() {
        return "Secured Endpoint :: GET - User controller";
    }

    @PostMapping
    public String post() {
        return "POST:: Admin controller";
    }
}
