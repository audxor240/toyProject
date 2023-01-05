package com.toyProject.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

public class UserDto {

    @Data
    @NoArgsConstructor
    public static class Save{
        private String userId;
        private String password;
        private String email;
    }
}
