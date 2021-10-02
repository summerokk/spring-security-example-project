package com.example.security.auth;

import com.google.common.collect.Lists;
import java.util.List;
import java.util.Optional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import static com.example.security.config.ApplicationUserRole.ADMIN;
import static com.example.security.config.ApplicationUserRole.ADMINTRAINEE;
import static com.example.security.config.ApplicationUserRole.STUDENT;

@Repository
public class UserDaoImpl implements UserDao {

    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserDaoImpl(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<User> getByUserName(String username) {
        return getAllUsers().stream().filter(user -> user.getUsername().equals(username)).findFirst();
    }

    private List<User> getAllUsers() {
        return Lists.newArrayList(
                new User(
                        STUDENT.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "dima",
                        true,
                        true,
                        true,
                        true
                ),
                new User(
                        ADMIN.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "fedor",
                        true,
                        true,
                        true,
                        true
                ),
                new User(
                        ADMINTRAINEE.getGrantedAuthorities(),
                        passwordEncoder.encode("password"),
                        "petr",
                        true,
                        true,
                        true,
                        true
                )
        );
    }
}
