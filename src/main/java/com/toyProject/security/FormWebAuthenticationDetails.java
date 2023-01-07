package com.toyProject.security;

import org.springframework.security.web.authentication.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

public class FormWebAuthenticationDetails extends WebAuthenticationDetails {

    private boolean remember;

    public FormWebAuthenticationDetails(HttpServletRequest request) {

        super(request);
        //remember-me 사용 여부 처리
        if(request.getParameter("remember-me") == null){
            remember = false;
        }else{
            remember = true;
        }


    }
    public boolean getRemember() {
        return remember;
    }
}
