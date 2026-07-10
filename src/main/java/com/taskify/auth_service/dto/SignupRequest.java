package com.taskify.auth_service.dto;

import lombok.Data;

@Data
public class SignupRequest {
    private String email;
    private String mobile;
    private String password;
}
