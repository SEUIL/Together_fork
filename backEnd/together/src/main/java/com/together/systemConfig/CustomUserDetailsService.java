package com.together.systemConfig;

import com.together.user.UserEntity;
import com.together.user.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    //Spring Security의 인증 과정에서 사용자 정보를 데이터베이스에서 가져오는 역할을 한다.

    private final UserRepository userRepository;

    /**
     * 데이터베이스에서 username(로그인 ID)으로 사용자를 조회한다.
     * 사용자가 존재하지 않으면 UsernameNotFoundException을 발생시킨다.
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //사용자 정보 조회
        UserEntity user = userRepository.findByUserLoginId(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

        // 이메일 인증 여부 확인
        if (!user.isEmailVerified()) {
            log.error("이메일 인증되지 않은 사용자 : {}", username);
            throw new IllegalArgumentException("이메일 인증이 완료되지 않았습니다.");
        }

        return new UserDetailsImpl(user);
    }
}
