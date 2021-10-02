package com.example.security.auth;

import java.util.Optional;

public interface UserDao {
    Optional<User> getByUserName(String username);
}
