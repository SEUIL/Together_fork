package com.together.user.dto;

import lombok.Data;
//import jakarta.validation.constraints.Email;
//import jakarta.validation.constraints.NotBlank;


@Data
public class UserSignUpRequestDto {

//    @NotBlank(message = "이름을 입력해주세요.")
    private String userName;

//    @Email(message = "올바른 이메일을 입력해주세요.")
//    @NotBlank(message = "이메일을 입력해주세요.")
    private String userEmail;

//    @NotBlank(message = "아이디를 입력해주세요.")
    private String userLoginId;

//    @NotBlank(message = "비밀번호를 입력해주세요.")
    private String password;

//    @NotBlank(message = "비밀번호 확인을 입력해주세요.")
    private String confirmPassword;

    private String userRole; // STUDENT or PROFESSOR

    private String studentNumber; // STUDENT일 경우 필수, PROFESSOR 경우 Null
}
