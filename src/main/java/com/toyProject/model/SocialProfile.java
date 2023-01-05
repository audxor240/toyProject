package com.toyProject.model;

import lombok.Data;

@Data
public class SocialProfile {

    public String resultcode;
    public String message;

    public Response response;

    @Data
    public class Response {

        public String id;
        public String email;

    }
}
