package com.security.service;

import com.security.model.User;
import com.security.model.UserPrinciple;
import com.security.repository.UserRepositoy;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MyUserDetailService implements UserDetailsService {

    private final UserRepositoy userRepositoy;
    private final PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(@NonNull String username) throws UsernameNotFoundException {

        User byUsername = userRepositoy.findByUsername(username);

        if (byUsername == null) {
            throw new UsernameNotFoundException("User Not Found : "+byUsername.getUsername());
        }

        return new UserPrinciple(byUsername);
    }

    public void registerUser(User user) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
            userRepositoy.save(user);
    }
}
