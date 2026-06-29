package com.godfathercapybara.capybara.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.godfathercapybara.capybara.model.User;

@Service
public class ValidateService {
    @Autowired
    private UserService userService;

    
    public String validateUsername(String username) {
        if (username.isEmpty()) {
            return "El campo nombre de usuario no puede ser nulo";
        }
        if(userService.existsByUsername(username)) {
            return "El nombre de usuario ya existe";
        }

        return null;
    }
   

    public String validateName(String name) {
        if (name.isEmpty()) {
            return "El campo nombre no puede ser nulo";
        }

        return null;
    }
    public String validatePassword(String password , String confirmPassword) {
        if (password.isEmpty()) {
            return "El campo contraseña no puede ser nulo";
        }
        if(password.length()<8) {
            return "La contraseña debe tener al menos 8 caracteres";
        }
        if(!password.equals(confirmPassword)) {
            return "Las contraseñas no coinciden";
        }

        return null;
    }
    public String validateEmail(String email) {
        if (email.isEmpty()) {
            return "El campo email no puede ser nulo";
        }
        if(userService.existsByEmail(email)) {
            return "El email ya existe";
        }

        return null;
    }
    public String validateLastName(String lastName) {
        if (lastName.isEmpty()) {
            return "El campo apellido no puede ser nulo";
        }

        return null;
    }

    public String validateUser(User user, String confirmPassword) {
        String usernameError = validateUsername(user.getUsername());
        if (usernameError != null) {
            return usernameError;
        }
       
        String passwordError = validatePassword(user.getPassword(), confirmPassword);
        if (passwordError != null) {
            return passwordError;
        }
        String emailError = validateEmail(user.getEmail());
        if (emailError != null) {
            return emailError;
        }
        return null; // User is valid
    }
    public String validateUpdatedUser(User user, String confirmPassword) {
      
        String nameError = validateName(user.getName());
        if (nameError != null) {
            return nameError;
        }
        String lastNameError =validateLastName(user.getLastName());
        if (lastNameError != null) {
            return lastNameError;
        }
       
        if(!user.getPassword().isEmpty()) {
            String passwordError = validatePassword(user.getPassword(), confirmPassword);
            if (passwordError != null) {
                return passwordError;
            }
        }

        return null; // User is valid
    }
}
