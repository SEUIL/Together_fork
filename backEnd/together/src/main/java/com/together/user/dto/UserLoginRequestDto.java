package com.together.user.dto;

//import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class UserLoginRequestDto {

//    @NotBlank(message = "아이디를 입력해 주세요.")
    private String userLoginId;

//    @NotBlank(message = "비밀번호를 입력해 주세요.")
    private String password;

}
