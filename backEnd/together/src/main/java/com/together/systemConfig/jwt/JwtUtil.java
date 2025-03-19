package com.together.systemConfig.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration}")
    private long expirationTime;

    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));

        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length < 32) {
            throw new IllegalArgumentException("JWT Secret Key must be at least 32 bytes long.");
        }

    }

    // JWT 토큰 생성
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    // JWT 토큰에서 사용자 정보 추출
    public String getUsernameFromToken(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody()
                    .getSubject();
        } catch (ExpiredJwtException e) {
            System.out.println("토큰이 만료되었습니다: " + e.getMessage());
            return null;
        } catch (JwtException | IllegalArgumentException e) {
            System.out.println("JWT 파싱 실패: " + e.getMessage());
            return null;
        }
    }

    // JWT 토큰 유효성 검사
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            System.out.println("토큰이 만료되었습니다: " + e.getMessage());
            return false;
        } catch (UnsupportedJwtException e) {
            System.out.println("지원되지 않는 JWT 형식입니다: " + e.getMessage());
            return false;
        } catch (MalformedJwtException e) {
            System.out.println("잘못된 JWT 형식입니다: " + e.getMessage());
            return false;
        } catch (SignatureException e) {
            System.out.println("JWT 서명 검증 실패: " + e.getMessage());
            return false;
        } catch (IllegalArgumentException e) {
            System.out.println("JWT 값이 비어있거나 잘못되었습니다: " + e.getMessage());
            return false;
        }
    }



}
