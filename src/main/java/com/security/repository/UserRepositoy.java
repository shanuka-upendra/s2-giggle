package com.security.repository;

import com.security.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@RequiredArgsConstructor
public class UserRepositoy {

    private final JdbcTemplate jdbcTemplate;

    public User findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = ?";

        User user = new User();
        List<User> users = jdbcTemplate.query(sql, new Object[]{username}, (rs, rowNum) -> {
            user.setId(rs.getLong("id"));
            user.setUsername(rs.getString("username"));
            user.setPassword(rs.getString("password"));
            user.setRole(rs.getString("role"));
            return user;
        });
        return user;
    }

    public void save(User user) {
        String sql = "INSERT INTO users (username, password, role) VALUES (?, ?, ?)";
        jdbcTemplate.update(sql, user.getUsername(), user.getPassword(), user.getRole());
    }

    /**
     * Find a user by ID
     * @param id the user ID
     * @return User if found, null otherwise
     */
    public User findById(Long id) {
        String sql = "SELECT * FROM users WHERE id = ?";
        List<User> users = jdbcTemplate.query(sql, new Object[]{id}, (rs, rowNum) -> {
            User user = new User();
            user.setId(rs.getLong("id"));
            user.setUsername(rs.getString("username"));
            user.setPassword(rs.getString("password"));
            user.setRole(rs.getString("role"));
            return user;
        });
        return users.isEmpty() ? null : users.get(0);
    }

    /**
     * Find all users
     * @return List of all users
     */
    public List<User> findAll() {
        String sql = "SELECT * FROM users";
        return jdbcTemplate.query(sql, (rs, rowNum) -> {
            User user = new User();
            user.setId(rs.getLong("id"));
            user.setUsername(rs.getString("username"));
            user.setPassword(rs.getString("password"));
            user.setRole(rs.getString("role"));
            return user;
        });
    }

    /**
     * Update an existing user
     * @param user the user to update
     */
    public void update(User user) {
        String sql = "UPDATE users SET username = ?, password = ?, role = ? WHERE id = ?";
        jdbcTemplate.update(sql, user.getUsername(), user.getPassword(), user.getRole(), user.getId());
    }

    /**
     * Delete a user by ID
     * @param id the user ID
     */
    public void deleteById(Long id) {
        String sql = "DELETE FROM users WHERE id = ?";
        jdbcTemplate.update(sql, id);
    }

    /**
     * Check if a user exists by username
     * @param username the username
     * @return true if user exists, false otherwise
     */
    public boolean existsByUsername(String username) {
        String sql = "SELECT COUNT(*) FROM users WHERE username = ?";
        Integer count = jdbcTemplate.queryForObject(sql, new Object[]{username}, Integer.class);
        return count != null && count > 0;
    }
}
