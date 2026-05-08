package com.security.controller;

import com.security.model.User;
import com.security.repository.UserRepositoy;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Admin Controller for managing team members (users) in the system.
 * Only ADMIN role users can access these endpoints.
 */
@RestController
@RequestMapping("/secure/admin/members")
@RequiredArgsConstructor
@PreAuthorize("hasRole('ADMIN')")
@Tag(name = "Admin Team Management", description = "APIs for managing team members - ADMIN only")
public class AdminController {

    private final UserRepositoy userRepository;
    private final PasswordEncoder passwordEncoder;

    /**
     * Get all team members
     *
     * @return List of all users in the system
     */
    @GetMapping
    @Operation(summary = "Get all team members", description = "Retrieve a list of all team members/users in the system")
    public ResponseEntity<Map<String, Object>> getAllMembers() {
        try {
            List<User> users = userRepository.findAll();
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("count", users.size());
            response.put("data", users);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return buildErrorResponse("Failed to retrieve team members", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Get a specific team member by ID
     *
     * @param id the user ID
     * @return User details if found
     */
    @GetMapping("/{id}")
    @Operation(summary = "Get team member by ID", description = "Retrieve details of a specific team member by their ID")
    public ResponseEntity<Map<String, Object>> getMemberById(@PathVariable Long id) {
        try {
            User user = userRepository.findById(id);
            if (user == null || user.getId() == null) {
                return buildErrorResponse("Team member not found with ID: " + id, HttpStatus.NOT_FOUND);
            }
            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("data", user);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return buildErrorResponse("Error retrieving team member", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Create a new team member
     *
     * @param user User object with username, password, and role
     * @return Created user details
     */
    @PostMapping
    @Operation(summary = "Create new team member", description = "Add a new team member to the system with username, password, and role")
    public ResponseEntity<Map<String, Object>> createMember(@RequestBody User user) {
        try {
            // Validation
            if (user.getUsername() == null || user.getUsername().trim().isEmpty()) {
                return buildErrorResponse("Username is required", HttpStatus.BAD_REQUEST);
            }
            if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
                return buildErrorResponse("Password is required", HttpStatus.BAD_REQUEST);
            }
            if (user.getRole() == null || user.getRole().trim().isEmpty()) {
                return buildErrorResponse("Role is required (USER, STAFF, MANAGER, ADMIN)", HttpStatus.BAD_REQUEST);
            }

            // Check if username already exists
            if (userRepository.existsByUsername(user.getUsername())) {
                return buildErrorResponse("Username already exists: " + user.getUsername(), HttpStatus.CONFLICT);
            }

            // Validate role
            String[] validRoles = {"USER", "STAFF", "MANAGER", "ADMIN"};
            String roleUpper = user.getRole().toUpperCase();
            boolean isValidRole = false;
            for (String validRole : validRoles) {
                if (validRole.equals(roleUpper)) {
                    isValidRole = true;
                    break;
                }
            }
            if (!isValidRole) {
                return buildErrorResponse("Invalid role. Allowed roles: USER, STAFF, MANAGER, ADMIN", HttpStatus.BAD_REQUEST);
            }

            // Encode password and set role
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            user.setRole(roleUpper);

            // Save user
            userRepository.save(user);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Team member created successfully");
            response.put("data", new HashMap<String, Object>() {{
                put("username", user.getUsername());
                put("role", user.getRole());
            }});
            return ResponseEntity.status(HttpStatus.CREATED).body(response);
        } catch (Exception e) {
            return buildErrorResponse("Failed to create team member: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Update an existing team member
     *
     * @param id   the user ID to update
     * @param user User object with updated information
     * @return Updated user details
     */
    @PutMapping("/{id}")
    @Operation(summary = "Update team member", description = "Update details of an existing team member by their ID")
    public ResponseEntity<Map<String, Object>> updateMember(@PathVariable Long id, @RequestBody User user) {
        try {
            // Check if user exists
            User existingUser = userRepository.findById(id);
            if (existingUser == null || existingUser.getId() == null) {
                return buildErrorResponse("Team member not found with ID: " + id, HttpStatus.NOT_FOUND);
            }

            // Update username if provided
            if (user.getUsername() != null && !user.getUsername().trim().isEmpty()) {
                if (!user.getUsername().equals(existingUser.getUsername()) &&
                        userRepository.existsByUsername(user.getUsername())) {
                    return buildErrorResponse("Username already exists: " + user.getUsername(), HttpStatus.CONFLICT);
                }
                existingUser.setUsername(user.getUsername());
            }

            // Update password if provided
            if (user.getPassword() != null && !user.getPassword().trim().isEmpty()) {
                existingUser.setPassword(passwordEncoder.encode(user.getPassword()));
            }

            // Update role if provided
            if (user.getRole() != null && !user.getRole().trim().isEmpty()) {
                String[] validRoles = {"USER", "STAFF", "MANAGER", "ADMIN"};
                String roleUpper = user.getRole().toUpperCase();
                boolean isValidRole = false;
                for (String validRole : validRoles) {
                    if (validRole.equals(roleUpper)) {
                        isValidRole = true;
                        break;
                    }
                }
                if (!isValidRole) {
                    return buildErrorResponse("Invalid role. Allowed roles: USER, STAFF, MANAGER, ADMIN", HttpStatus.BAD_REQUEST);
                }
                existingUser.setRole(roleUpper);
            }

            // Save updated user
            userRepository.update(existingUser);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Team member updated successfully");
            response.put("data", new HashMap<String, Object>() {{
                put("id", existingUser.getId());
                put("username", existingUser.getUsername());
                put("role", existingUser.getRole());
            }});
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return buildErrorResponse("Failed to update team member: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Delete a team member by ID
     *
     * @param id the user ID to delete
     * @return Confirmation of deletion
     */
    @DeleteMapping("/{id}")
    @Operation(summary = "Delete team member", description = "Remove a team member from the system by their ID")
    public ResponseEntity<Map<String, Object>> deleteMember(@PathVariable Long id) {
        try {
            User user = userRepository.findById(id);
            if (user == null || user.getId() == null) {
                return buildErrorResponse("Team member not found with ID: " + id, HttpStatus.NOT_FOUND);
            }

            userRepository.deleteById(id);

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("message", "Team member deleted successfully");
            response.put("data", new HashMap<String, Object>() {{
                put("deletedId", id);
                put("username", user.getUsername());
            }});
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return buildErrorResponse("Failed to delete team member: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Get team members filtered by role
     *
     * @param role the role to filter by (USER, STAFF, MANAGER, ADMIN)
     * @return List of users with the specified role
     */
    @GetMapping("/filter/role")
    @Operation(summary = "Get team members by role", description = "Retrieve team members filtered by a specific role")
    public ResponseEntity<Map<String, Object>> getMembersByRole(@RequestParam String role) {
        try {
            List<User> allUsers = userRepository.findAll();
            List<User> filteredUsers = allUsers.stream()
                    .filter(u -> u.getRole() != null && u.getRole().equalsIgnoreCase(role))
                    .toList();

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("role", role.toUpperCase());
            response.put("count", filteredUsers.size());
            response.put("data", filteredUsers);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return buildErrorResponse("Failed to retrieve team members by role", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Get statistics about team members
     *
     * @return Count of members by role
     */
    @GetMapping("/statistics")
    @Operation(summary = "Get team statistics", description = "Retrieve statistics about team members including count by role")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        try {
            List<User> users = userRepository.findAll();

            Map<String, Integer> roleCount = new HashMap<>();
            for (User user : users) {
                String role = user.getRole() != null ? user.getRole() : "UNKNOWN";
                roleCount.put(role, roleCount.getOrDefault(role, 0) + 1);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("status", "success");
            response.put("totalMembers", users.size());
            response.put("membersByRole", roleCount);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return buildErrorResponse("Failed to retrieve statistics", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Helper method to build error responses
     */
    private ResponseEntity<Map<String, Object>> buildErrorResponse(String message, HttpStatus status) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("status", "error");
        errorResponse.put("message", message);
        return ResponseEntity.status(status).body(errorResponse);
    }
}
