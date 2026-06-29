package com.godfathercapybara.capybara.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

@Component
public class DatabaseInitializer {

        @Autowired
        private UserService userService;
        @Autowired
        private PasswordEncoder passwordEncoder;

        @PostConstruct
        public void init() {

        }

}
