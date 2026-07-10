package com.taskify.auth_service.service;

import com.taskify.auth_service.dto.AuthResponse;
import com.taskify.auth_service.dto.LoginRequest;
import com.taskify.auth_service.dto.SignupRequest;
import com.taskify.auth_service.exception.AuthException;
import com.taskify.auth_service.model.User;
import com.taskify.auth_service.repository.UserRepository;
import com.taskify.auth_service.security.JwtTokenProvider;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final RedisTemplate<String, String> redisTemplate;
    private final JwtTokenProvider tokenProvider;

    public AuthService(UserRepository userRepository,
                       BCryptPasswordEncoder passwordEncoder,
                       RedisTemplate<String, String> redisTemplate,
                       JwtTokenProvider tokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.redisTemplate = redisTemplate;
        this.tokenProvider = tokenProvider;
    }

    public void registerUser(SignupRequest request) {
        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
            throw new AuthException("auth.error.email-exists");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setMobile(request.getMobile());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setVerified(false);
        userRepository.save(user);

        String otp = String.format("%06d", new Random().nextInt(999999));
        String redisKey = "OTP:" + request.getEmail();
        redisTemplate.opsForValue().set(redisKey, otp, 5, TimeUnit.MINUTES);

        System.out.println(">>> [MOCK SERVICE] OTP for " + request.getEmail() + " -> " + otp);
    }

    public AuthResponse verifyOtp(String email, String enteredOtp) {
        String redisKey = "OTP:" + email;
        String cachedOtp = redisTemplate.opsForValue().get(redisKey);

        if (cachedOtp == null) {
            throw new AuthException("auth.error.otp-expired");
        }

        if (!cachedOtp.equals(enteredOtp)) {
            throw new AuthException("auth.error.otp-invalid");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("auth.error.user-mismatch"));

        user.setVerified(true);
        userRepository.save(user);
        redisTemplate.delete(redisKey);

        String accessToken = tokenProvider.generateAccessToken(email, user.getRole().name());
        String refreshToken = tokenProvider.generateRefreshToken(email, user.getRole().name());

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }

    public AuthResponse loginUser(LoginRequest request) {
        // 1. Check if user exists
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthException("auth.error.invalid-credentials"));

        // 2. Verify encrypted password match
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new AuthException("auth.error.invalid-credentials");
        }

        // 3. Prevent unverified users from logging in
        if (!user.isVerified()) {
            throw new AuthException("auth.error.not-verified");
        }

        // 4. Issue fresh tokens
        String accessToken = tokenProvider.generateAccessToken(user.getEmail(), user.getRole().name());
        String refreshToken = tokenProvider.generateRefreshToken(user.getEmail(), user.getRole().name());

        // 5. Save the long-lived refresh token session to the database
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }

    public AuthResponse refreshAccessToken(String incomingRefreshToken) {
        // 1. Run structural/expiration check on the JWT token string itself
        if (!tokenProvider.validateToken(incomingRefreshToken)) {
            throw new AuthException("auth.error.token-invalid");
        }

        // 2. Extract email from token payload
        String email = tokenProvider.getEmailFromToken(incomingRefreshToken);

        // 3. Match against database record to prevent session reuse hijacking
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new AuthException("auth.error.token-invalid"));

        if (user.getRefreshToken() == null || !user.getRefreshToken().equals(incomingRefreshToken)) {
            throw new AuthException("auth.error.token-invalid");
        }

        // 4. Issue pristine new Access Token
        String newAccessToken = tokenProvider.generateAccessToken(user.getEmail(), user.getRole().name());

        return AuthResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(incomingRefreshToken)
                .email(user.getEmail())
                .role(user.getRole().name())
                .build();
    }
}
