package com.security.model;

import lombok.Getter;

@Getter
public enum Permission {
    // Admin-related permissions
    ADMIN_READ("admin:read"), // Permission to read admin data
    ADMIN_CREATE("admin:create"), // Permission to create new admin data

    // Member-related permissions
    MEMBER_READ("management:read"), // Permission to read member data
    MEMBER_CREATE("management:create"), // Permission to create new member data

    ; // Required to separate enum constants

    // Private field to store the permission string
    private final String permission;

    // Constructor to initialize the permission string
    Permission(String permission) {
        this.permission = permission;
    }
}
}
