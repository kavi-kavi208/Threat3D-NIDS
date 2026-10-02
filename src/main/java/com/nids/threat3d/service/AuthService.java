package com.nids.threat3d.service;

import com.nids.threat3d.exception.ResourceNotFoundException;
import com.nids.threat3d.exception.ThreatApiException;
import com.nids.threat3d.model.Role;
import com.nids.threat3d.model.User;
import com.nids.threat3d.model.dto.AuthRequest;
import com.nids.threat3d.model.dto.AuthResponse;
import com.nids.threat3d.model.dto.RegisterRequest;
import com.nids.threat3d.model.dto.UserProfileResponse;
import com.nids.threat3d.repository.UserRepository;
import com.nids.threat3d.security.JwtService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtService jwtService,
                       AuthenticationManager authenticationManager) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }

    @Transactional
    public AuthResponse login(AuthRequest request) {
        // Authenticate via Spring Security AuthenticationManager
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
        );

        User user = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + request.getUsername()));

        String token = jwtService.generateToken(user, user.getRole().name());

        return new AuthResponse(
                token,
                user.getUsername(),
                user.getFullName(),
                user.getRole().name(),
                jwtService.getJwtExpirationMs()
        );
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new ThreatApiException(HttpStatus.CONFLICT, "Username already registered: " + request.getUsername());
        }

        if (request.getEmail() != null && !request.getEmail().isBlank() && userRepository.existsByEmail(request.getEmail())) {
            throw new ThreatApiException(HttpStatus.CONFLICT, "Email already registered: " + request.getEmail());
        }

        Role assignedRole = request.getRole() != null ? request.getRole() : Role.ROLE_STUDENT;

        User newUser = new User(
                request.getUsername(),
                passwordEncoder.encode(request.getPassword()),
                request.getFullName(),
                request.getEmail(),
                assignedRole
        );

        User savedUser = userRepository.save(newUser);
        String token = jwtService.generateToken(savedUser, savedUser.getRole().name());

        return new AuthResponse(
                token,
                savedUser.getUsername(),
                savedUser.getFullName(),
                savedUser.getRole().name(),
                jwtService.getJwtExpirationMs()
        );
    }

    @Transactional(readOnly = true)
    public UserProfileResponse getCurrentUserProfile(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found: " + username));

        return new UserProfileResponse(
                user.getId(),
                user.getUsername(),
                user.getFullName(),
                user.getEmail(),
                user.getRole().name(),
                user.isEnabled(),
                user.getCreatedAt()
        );
    }
}
