package com.toyProject.security;

import com.toyProject.properties.AppProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.math.BigInteger;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SocialLoginSupport {

    private final AppProperties appProperties;

    public String getSocialOauthUrl(String type, String redirectUri, String state) {

        if (type.equals("GOOGLE")) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(appProperties.getGoogleRequestTokenUri())
                    .queryParam("client_id", appProperties.getGoogleClientId())
                    .queryParam("scope", "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile")
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("response_type", "code")
                    .queryParam("state", state);
            return builder.toUriString();
        } else if (type.equals("NAVER")) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(appProperties.getNaverRequestTokenUri())
                    .queryParam("client_id", appProperties.getNaverClientId())
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("response_type", "code")
                    .queryParam("state", state);
            return builder.toUriString();
        } else if (type.equals("KAKAO")) {
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(appProperties.getKakaoRequestTokenUri())
                    .queryParam("client_id", appProperties.getKakaoClientId())
                    .queryParam("redirect_uri", redirectUri)
                    .queryParam("response_type", "code")
                    .queryParam("state", state);
            return builder.toUriString();
        }
        return null;


        /*
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(appProperties.getKakaoRequestTokenUri())
                .queryParam("client_id", appProperties.getKakaoClientId())
                .queryParam("redirect_uri", redirectUri)
                .queryParam("response_type", "code")
                .queryParam("state", state);
        return builder.toUriString();
        */

    }

    public void setSocialOauthUrl(HttpServletRequest request, Model model) {
        String state = generateState();
        request.getSession().setAttribute("state", state);

        model.addAttribute("oauthUrlForGoogle", getSocialOauthUrl("GOOGLE",appProperties.getHost() + "/auth/google/callback", state));
        model.addAttribute("oauthUrlForNaver", getSocialOauthUrl("NAVER",appProperties.getHost() + "/auth/naver/callback", state));
        model.addAttribute("oauthUrlForKakao", getSocialOauthUrl("KAKAO",appProperties.getHost()+"/auth/kakao/callback", state));


    }

    public static String generateState() {
        SecureRandom random = new SecureRandom();
        return new BigInteger(130, random).toString(32);
    }
}
