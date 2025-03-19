package com.together.user;

import com.together.systemConfig.jwt.JwtUtil;
import com.together.user.dto.UserLoginRequestDto;
import com.together.user.dto.UserSignUpRequestDto;
import com.together.user.email.EmailService;
import com.together.user.email.VerificationCodeService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
@RestController
@RequestMapping("/auth")
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final VerificationCodeService verificationCodeService;
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    /**
     *  로그인: JWT 발급 및 HttpOnly 쿠키 설정
     */
    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserLoginRequestDto loginRequest, HttpServletResponse response) {
        String token = userService.login(loginRequest);

        Cookie cookie = new Cookie("JWT_TOKEN", token);
        cookie.setHttpOnly(true);
        cookie.setPath("/"); // 모든 경로에서 접근 가능
        response.addCookie(cookie);

        return ResponseEntity.ok("로그인 성공, 토큰 : " + token);
    }

    /**
     *  로그아웃: JWT 쿠키 삭제
     */
    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletResponse response) {
        Cookie cookie = new Cookie("JWT_TOKEN", null);
        cookie.setMaxAge(0);
        cookie.setPath("/");
        response.addCookie(cookie);

        return ResponseEntity.ok("로그아웃이 완료되었습니다. ");
    }

    /**
     *  회원가입
     */
    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody UserSignUpRequestDto requestDto) {
        return userService.registerUser(requestDto);
    }

    /**
     * 현재 사용자 확인
     */
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        // 🟢 JWT 쿠키에서 토큰 가져오기
        String token = getJwtFromCookie(request);

        // 🟠 토큰이 없거나 유효하지 않으면 401 반환
        if (token == null || !jwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("유효하지 않은 토큰입니다.");
        }

        try {
            // ✅ JWT에서 사용자 정보 추출
            String username = jwtUtil.getUsernameFromToken(token);

            // ✅ 사용자 정보를 JSON 형태로 반환
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("username", username);

            return ResponseEntity.ok(userInfo);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("토큰 검증에 실패하였습니다.");
        }
    }

    // 🟢 JWT를 HttpOnly 쿠키에서 가져오는 메서드
    private String getJwtFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) {
            return null;
        }
        for (Cookie cookie : request.getCookies()) {
            if ("JWT_TOKEN".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    // 아이디 찾기 요청 (이메일로 인증 코드 전송)
    @PostMapping("/find-id")
    public ResponseEntity<String> findUserId(@RequestParam String email) throws MessagingException {
        Optional<UserEntity> user = userRepository.findByUserEmail(email);
        if (user.isEmpty()) {
            return ResponseEntity.badRequest().body("해당 이메일로 가입된 계정이 없습니다.");
        }

        String code = emailService.generateVerificationCode();
        verificationCodeService.saveVerificationCode(email, code);
        emailService.sendVerificationEmail(email, code);

        return ResponseEntity.ok("이메일로 인증 코드가 전송되었습니다.");
    }

    // 인증 코드 확인 후 아이디 반환
    @PostMapping("/find-id/verify")
    public ResponseEntity<String> verifyAndReturnUserId(@RequestParam String email, @RequestParam String code) {
        if (!verificationCodeService.verifyCode(email, code)) {
            return ResponseEntity.badRequest().body("인증 코드가 올바르지 않습니다.");
        }

        UserEntity user = userRepository.findByUserEmail(email).orElseThrow();
        return ResponseEntity.ok("회원님의 아이디는 " + user.getUserLoginId() + " 입니다.");
    }

    // 비밀번호 찾기 요청 (이메일로 인증 코드 전송)
    @PostMapping("/find-password")
    public ResponseEntity<String> findUserPassword(@RequestParam String email) throws MessagingException {
        Optional<UserEntity> user = userRepository.findByUserEmail(email);
        if (user.isEmpty()) {
            return ResponseEntity.badRequest().body("해당 이메일로 가입된 계정이 없습니다.");
        }

        String code = emailService.generateVerificationCode();
        verificationCodeService.saveVerificationCode(email, code);
        emailService.sendVerificationEmail(email, code);
        return ResponseEntity.ok("이메일로 인증 코드가 전송되었습니다.");
    }

    // 인증 코드 확인 후 비밀번호 변경
    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam String email, @RequestParam String code, @RequestParam String newPassword) {
        if (!verificationCodeService.verifyCode(email, code)) {
            return ResponseEntity.badRequest().body("인증 코드가 올바르지 않습니다.");
        }

        UserEntity user = userRepository.findByUserEmail(email).orElseThrow();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        return ResponseEntity.ok("비밀번호가 성공적으로 변경되었습니다.");
    }
}
