package com.together.user;

import com.together.systemConfig.jwt.JwtUtil;
import com.together.user.dto.UserLoginRequestDto;
import com.together.user.dto.UserSignUpRequestDto;
import com.together.user.student.StudentEntity;
import com.together.user.student.StudentRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final StudentRepository studentRepository;
    private final JwtUtil jwtUtil;


    /** 회원가입
     *
     * 제공된 요청 정보를 바탕으로 새로운 사용자를 등록, 사용자는 학생(STUDENT) 또는 교수(PROFESSOR)일 수 있으며,
     * 해당 역할에 따라 정보를 저장
     *
     * 프론트에서 학생 or 교수를 선택했을때 해당 입력 필드를 보여주고
     * 입력이 완료되었을때 UserSignUpRequestDto에 해당하는 변수들을 서버로 보내주면 됨
     *
     * @param requestDto {@link UserSignUpRequestDto}의 객체로, 사용자 가입 정보를 포함:
     *                   - userName: 사용자의 이름.
     *                   - userEmail: 사용자의 이메일 주소.
     *                   - userLoginId: 사용자의 로그인 ID.
     *                   - password: 사용자가 제공한 비밀번호.
     *                   - confirmPassword: 비밀번호 확인 값 (비밀번호 유효성 검사를 위해 필요).
     *                   - userRole: 사용자의 역할. "STUDENT" 또는 "PROFESSOR"만 허용됨.
     *                   - studentNumber: 학생 번호. 사용자 역할이 "STUDENT"인 경우 필수 입력 값.
     * @throws IllegalArgumentException 다음의 경우 예외를 발생:
     *                                  - 비밀번호가 확인 비밀번호와 일치하지 않는 경우.
     *                                  - 역할이 "STUDENT"이고 학생 번호가 제공되지 않은 경우.
     *                                  - 제공된 사용자 역할이 "STUDENT" 또는 "PROFESSOR"가 아닌 경우.
     */
    @Transactional
    public ResponseEntity<String> registerUser(UserSignUpRequestDto requestDto) {
        // 비밀번호 일치 여부 확인
        if (!requestDto.getPassword().equals(requestDto.getConfirmPassword())) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        // 비밀번호 암호화
        String encodedPassword = passwordEncoder.encode(requestDto.getPassword());

        // UserRole 확인
        if ("STUDENT".equals(requestDto.getUserRole())) {
            if (requestDto.getStudentNumber() == null || requestDto.getStudentNumber().isEmpty()) {
                throw new IllegalArgumentException("학생의 경우 학번이 필수입니다.");
            }

            StudentEntity student = new StudentEntity();
            student.setUserName(requestDto.getUserName());
            student.setUserEmail(requestDto.getUserEmail());
            student.setUserLoginId(requestDto.getUserLoginId());
            student.setPassword(encodedPassword);
            student.setRole(UserEntity.UserRole.STUDENT);
            student.setStudentNumber(requestDto.getStudentNumber()); // 학번 추가

            studentRepository.save(student);
        }
        else if ("PROFESSOR".equals(requestDto.getUserRole())) {
            UserEntity professor = new UserEntity();
            professor.setUserName(requestDto.getUserName());
            professor.setUserEmail(requestDto.getUserEmail());
            professor.setUserLoginId((requestDto.getUserLoginId()));
            professor.setPassword(encodedPassword);
            professor.setRole(UserEntity.UserRole.PROFESSOR);

            userRepository.save(professor);
        }
        else {
            throw new IllegalArgumentException("올바른 사용자 유형이 아닙니다.");
        }
        return ResponseEntity.ok("회원가입이 완료되었습니다.");
    }

    /**
     * ✅ 로그인 로직 (JWT 발급)
     */
    public String login(UserLoginRequestDto requestDto) {
        UserEntity user = userRepository.findByUserLoginId(requestDto.getUserLoginId())
                .orElseThrow(() -> new IllegalArgumentException("잘못된 아이디 또는 비밀번호입니다."));

        if (!passwordEncoder.matches(requestDto.getPassword(), user.getPassword())) {
            throw new IllegalArgumentException("잘못된 아이디 또는 비밀번호입니다.");
        }

        return jwtUtil.generateToken(user.getUserLoginId());
    }

    public Optional<UserEntity> findUserByUsername(String userLoginId){
        return userRepository.findByUserLoginId(userLoginId);
    }

    public Optional<UserEntity> findUserByEmail(String userEmail){
        return userRepository.findByUserEmail(userEmail);
    }
}
