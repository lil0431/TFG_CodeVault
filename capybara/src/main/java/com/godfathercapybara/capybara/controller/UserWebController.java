package com.godfathercapybara.capybara.controller;

import java.io.IOException;
import java.security.Principal;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.godfathercapybara.capybara.model.User;
import com.godfathercapybara.capybara.service.UserService;
import com.godfathercapybara.capybara.service.ValidateService;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


@Controller
public class UserWebController {

	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private ValidateService validateService;

	@Autowired
	private UserService userService;

	@GetMapping("/")
	public String showHome(Model model, HttpServletRequest request) {
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			model.addAttribute("logged", true);
			Optional<User> userOptional = userService.findByUsername(principal.getName());
			if (userOptional.isPresent()) {
				User user = userOptional.get();
				model.addAttribute("user", user);
				model.addAttribute("isEmployee", 
					user.getRoles() != null && !user.getRoles().isEmpty() && 
					!user.getRoles().contains("CLIENTE") || 
					user.getRoles().contains("ADMIN") || 
					user.getRoles().contains("VENTAS") || 
					user.getRoles().contains("RECEPCIONISTA"));
			}
		} else {
			model.addAttribute("logged", false);
			model.addAttribute("isEmployee", false);
		}
		return "index";
	}
	
	@GetMapping("/employee-portal")
	public String showEmployeePortal(Model model, HttpServletRequest request) {
		Principal principal = request.getUserPrincipal();
		if (principal == null) {
			return "redirect:/login";
		}
		
		Optional<User> userOptional = userService.findByUsername(principal.getName());
		if (!userOptional.isPresent()) {
			return "redirect:/login";
		}
		
		User user = userOptional.get();
		// Verificar que sea empleado (no solo cliente)
		if (user.getRoles() == null || user.getRoles().isEmpty() || 
			(user.getRoles().size() == 1 && user.getRoles().contains("CLIENTE"))) {
			return "redirect:/";
		}
		
		model.addAttribute("user", user);
		return "employee-portal";
	}

	@GetMapping("/upload")
	public String showUpload(Model model, HttpServletRequest request) {
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			model.addAttribute("logged", true);
			Optional<User> userOptional = userService.findByUsername(principal.getName());
			if (userOptional.isPresent()) {
				User user = userOptional.get();
				model.addAttribute("user", user);
			}
		} else {
			model.addAttribute("logged", false);
		}
		return "upload";
	}

	@GetMapping("/my-analyses")
	public String showAnalyses(Model model, HttpServletRequest request) {
		Principal principal = request.getUserPrincipal();
		if (principal == null) {
			return "redirect:/login";
		}
		
		Optional<User> userOptional = userService.findByUsername(principal.getName());
		if (!userOptional.isPresent()) {
			return "redirect:/login";
		}
		
		User user = userOptional.get();
		model.addAttribute("user", user);
		return "my-analyses";
	}

	@GetMapping("/login")
	public String login() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || auth instanceof AnonymousAuthenticationToken) {
			return "login";
		} else {
			return "redirect:/me";
		}
	}

	@RequestMapping("/loginerror")
	public String loginerror() {

		return "loginerror";
	}

	@GetMapping("/signup")
	public String register() {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null || auth instanceof AnonymousAuthenticationToken) {
			return "signup";
		} else {
			return "redirect:/me";
		}
	}

	@PostMapping("/signup")
	public String processRegister(Model model, @ModelAttribute User user, String confirmPassword) {

		if (validateService.validateUser(user, confirmPassword) != null) {
			model.addAttribute("error", validateService.validateUser(user, confirmPassword));
			model.addAttribute("user", user);
			return "signup";
		} else {
			user.setPassword(passwordEncoder.encode(user.getPassword()));
			userService.save(user);
			String success = "Usuario " + user.getUsername() + " registrado con éxito.";
			model.addAttribute("user", user);
			model.addAttribute("success", success);
			return "private";
		}
	}

	@GetMapping("/users")
	public String showUsers(Model model) {
		model.addAttribute("users", userService.findAll());
		return "users";
	}

	@GetMapping("/me")
	public String privatePage(Model model) {

		return "private";
	}

	@GetMapping("/users/{id}/delete")
	public String deleteUser(Model model, @PathVariable long id, HttpServletRequest request,HttpServletResponse response) throws ServletException{
		Optional<User> user = userService.findById(id);
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			String name = principal.getName();
			Optional<User> userOptional = userService.findByUsername(name);
			User userLogged = userOptional.get();
			if ((userOptional.isPresent()) && (userService.isUser(userLogged.getId(), id)|| request.isUserInRole("ADMIN"))) {
				userService.delete(id);
				model.addAttribute("name", user.get().getUsername());
				if(userService.isUser(userLogged.getId(), id)){
				request.logout();
				response.setHeader("Set-Cookie", "token=; HttpOnly; Path=/; Max-Age=0");
				}
				return "removedUser";
			} else {
				return "redirect:/login";
			}
		} else {
			return "redirect:/login";
		}

	}
	@GetMapping("/users/{id}")
	public String getUser(@PathVariable long id, Model model, HttpServletRequest request) {
		Principal principal = request.getUserPrincipal();
		if(principal !=null)
		{
			String name = principal.getName();
			Optional<User> userOptionalLogged = userService.findByUsername(name);
			User userLogged = userOptionalLogged.get();
			Optional<User> user = userService.findById(id);
			if((userOptionalLogged.isPresent()) && (userService.isUser(userLogged.getId(), id)|| request.isUserInRole("ADMIN"))){
				model.addAttribute("user", user.get());
				return "private";
			}
			else{
				return "redirect:/login";
			}

		}
		else{
			return "redirect:/login";
		
		}
	}
	

	@GetMapping("/users/{id}/edit")
	public String showEditUserForm(@PathVariable("id") long id, Model model, HttpServletRequest request) {
		Principal principal = request.getUserPrincipal();
		if (principal != null) {
			String name = principal.getName();
			Optional<User> userOptional = userService.findByUsername(name);
			User userLogged = userOptional.get();
			if ((userOptional.isPresent()) && (userService.isUser(userLogged.getId(), id)|| request.isUserInRole("ADMIN"))) {
				User user = userService.findUserById(id);
				model.addAttribute("user", user);
				return "editPrivatePage";
			} else {
				return "redirect:/login";
			}
		} else {
			return "redirect:/login";

		}
	}

	@PostMapping("/users/{id}/edit")
	public String processEditUserForm(Model model, @PathVariable("id") long id, @ModelAttribute User updatedUser) throws IOException {
		String confirmPassword = updatedUser.getPassword();
		String error = validateService.validateUpdatedUser(updatedUser, confirmPassword);
		if (error != null) {
			model.addAttribute("error",  error);
			return "editPrivatePage";
		}
		updatedUser.setId(id);
		userService.updateUser(updatedUser, id);

		return "redirect:/";
	}

	@ModelAttribute
	public void addAttributes(Model model, HttpServletRequest request) {

		Principal principal = request.getUserPrincipal();

		if (principal != null) {

			model.addAttribute("logged", true);
			String name = principal.getName();
			Optional<User> userOptional = userService.findByUsername(name);
			User user = userOptional.get();
			model.addAttribute("user", user);
			model.addAttribute("admin", request.isUserInRole("ADMIN"));

		} else {
			model.addAttribute("logged", false);
		}
	}

}
