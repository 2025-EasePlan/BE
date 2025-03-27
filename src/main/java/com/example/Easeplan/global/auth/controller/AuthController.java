package com.example.Easeplan.global.auth.controller;

import com.example.Easeplan.global.auth.dto.SignInRequest;
import com.example.Easeplan.global.auth.dto.SignUpRequest;
import com.example.Easeplan.global.auth.dto.TokenResponse;
import com.example.Easeplan.global.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // 커스텀 응답 클래스
    public static class CustomResponse<T> {
        private String message;
        private T data;

        public CustomResponse(String message, T data) {
            this.message = message;
            this.data = data;
        }

        // Getter
        public String getMessage() { return message; }
        public T getData() { return data; }
    }

    @PostMapping("/signUp")
    public ResponseEntity<CustomResponse<TokenResponse>> signUp(@RequestBody SignUpRequest request) {
        if (authService.findByEmail(request.email()).isPresent()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new CustomResponse<>("이미 존재하는 이메일입니다.", null));
        }
        authService.signUp(request);
        SignInRequest signInRequest = new SignInRequest(request.email(), request.password());
        TokenResponse response = authService.signIn(signInRequest);

        return ResponseEntity.status(HttpStatus.CREATED).body(new CustomResponse<>("회원가입 및 로그인에 성공했습니다.", response));
    }

    @PostMapping("/signIn")
    public ResponseEntity<CustomResponse<TokenResponse>> signIn(@RequestBody SignInRequest request) {
        TokenResponse response = authService.signIn(request);
        return ResponseEntity.status(HttpStatus.OK).body(new CustomResponse<>("로그인에 성공했습니다.", response));
    }
}
