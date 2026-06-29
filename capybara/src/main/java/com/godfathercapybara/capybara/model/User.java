package com.godfathercapybara.capybara.model;

import java.util.ArrayList;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonView;

import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity(name="USERS")
@Table(uniqueConstraints = @UniqueConstraint(columnNames = "username"))
public class User {

    public interface Basic {
    }

    @Id
    @JsonView(Basic.class)
    private Long id;
	
    @JsonView(Basic.class)
	private String name;

    @JsonView(Basic.class)
	private String lastName;

    @JsonView(Basic.class)
	private String email;

    @JsonView(Basic.class)
    private String username;
    
    private String password;

    // Nuevos campos del JSON
    @JsonView(Basic.class)
    private String title; // Cargo/Título (ej: "CISO", "SOC Manager")
    
    @JsonView(Basic.class)
    private String department; // Departamento
    
    @JsonView(Basic.class)
    private String location; // Ubicación (ej: "Dallas, TX, US")
    
    @JsonView(Basic.class)
    private String handle; // Handle de usuario (ej: "@emartin-ciso")
    
    @JsonView(Basic.class)
    @ElementCollection(fetch = FetchType.EAGER)
    private List<String> skills = new ArrayList<>(); // Habilidades
    
    @JsonView(Basic.class)
    private String summary; // Resumen/Descripción

    @ElementCollection(fetch = FetchType.EAGER)
    @JsonView(Basic.class)
    private List<String> roles = new ArrayList<>(); // Roles: ADMIN, VENTAS, CLIENTE, RECEPCIONISTA

   
	public User() {
	}
	public User(String username, String encodedPassword, String... roles) {
		this.username = username;
		this.password = encodedPassword;
		this.roles = List.of(roles);
	}
	public User(String username, String name, String email, String lastName, String encodedPassword, String... roles) {
		this.name = name;
		this.email = email;
		this.lastName = lastName;
		this.username = username;
		this.password = encodedPassword;
		this.roles = List.of(roles);
	}
	public void setId(long id)
	{
		this.id=id;
	
	}
	public long getId()
	{
		return this.id;
	}
	public String getUsername() {
		return this.username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return this.password;
	}

	public void setPassword(String encodedPassword) {
		this.password = encodedPassword;
	}

	public String getName() {
		return this.name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getLastName() {
		return this.lastName;
	}
	public void setLastName(String lastName) {
		this.lastName = lastName;
	}
	public void setEmail(String email) {
		this.email = email;
	}
	public String getEmail() {
		return this.email;
	}

	public List<String> getRoles() {
		return roles;
	}

	public void setRoles(List<String> roles) {
		this.roles = roles;
	}
	
	// Getters y Setters para nuevos campos
	public String getTitle() {
		return title;
	}
	
	public void setTitle(String title) {
		this.title = title;
	}
	
	public String getDepartment() {
		return department;
	}
	
	public void setDepartment(String department) {
		this.department = department;
	}
	
	public String getLocation() {
		return location;
	}
	
	public void setLocation(String location) {
		this.location = location;
	}
	
	public String getHandle() {
		return handle;
	}
	
	public void setHandle(String handle) {
		this.handle = handle;
	}
	
	public List<String> getSkills() {
		return skills;
	}
	
	public void setSkills(List<String> skills) {
		this.skills = skills;
	}
	
	public String getSummary() {
		return summary;
	}
	
	public void setSummary(String summary) {
		this.summary = summary;
	}

}
