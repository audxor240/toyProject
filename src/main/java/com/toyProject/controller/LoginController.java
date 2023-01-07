package com.toyProject.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.toyProject.common.HttpClient;
import com.toyProject.common.HttpResult;
import com.toyProject.dto.UserDto;
import com.toyProject.model.*;
import com.toyProject.properties.AppProperties;
import com.toyProject.repository.UserRepository;
import com.toyProject.security.JwtTokenProvider;
import com.toyProject.security.SocialLoginSupport;
import com.toyProject.service.UserService;
//import net.sf.json.JSONException;
//import net.sf.json.JSONObject;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Controller
public class LoginController {
    @Value("${cos.key}")
    private String cosKey;

    @Autowired
    private SocialLoginSupport socialLoginSupport;

    @Autowired
    private UserService userService;

    @Autowired
    private AppProperties appProperties;

    @Autowired
    private AuthenticationManager authenticationManager;


    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private UserRepository userRepository;

    // 로그인
    /*@PostMapping("/login")
    public String login(@RequestBody Map<String, String> user) {
        //log.info("user email = {}", user.get("email"));
        User member = userRepository.findByEmail(user.get("email"))
                .orElseThrow(() -> new IllegalArgumentException("가입되지 않은 E-MAIL 입니다."));

        return jwtTokenProvider.createToken(member.getUsername(), member.getRoles());
    }*/

    @GetMapping("/auth/loginForm")
    public String loginForm(Model model, HttpServletRequest request){

        socialLoginSupport.setSocialOauthUrl(request, model);

        return "/pages/loginForm";
    }

    @GetMapping("/auth/{social}/callback")
    public String naver_callback(String code, @PathVariable String social,
                                HttpServletRequest request, HttpServletResponse res) {	//@ResponseBody =  DATA를 리턴해주는 컨트롤러 함수

        String client_id = "";
        String client_secret = "";
        String access_token_uri = "";
        String api_uri = "";
        switch (social){
            case "kakao":
                client_id = appProperties.getKakaoClientId();
                access_token_uri = appProperties.getKakaoAccessTokenUri();
                api_uri = appProperties.getKakaoApiUri();
                break;
            case "naver":
                client_id = appProperties.getNaverClientId();
                access_token_uri = appProperties.getNaverAccessTokenUri();
                api_uri = appProperties.getNaverApiUri();
                client_secret = appProperties.getNaverClientSecret();
                break;
            case "google":
                client_id = appProperties.getGoogleClientId();
                access_token_uri = appProperties.getGoogleAccessTokenUri();
                api_uri = appProperties.getGoogleApiUri();
                client_secret = appProperties.getGoogleClientSecret();
                break;
        }

        // POST 방식으로 key=value 데이터를 요청
        RestTemplate rt = new RestTemplate();

        //HttpHeader 오브젝트 생성
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        //HttpBody 오브젝트 생성
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        //params.add("grant_type", "authorization_code");
        //params.add("client_id", "828515077fb732a029b804dbd9837321");
        //params.add("redirect_uri", "http://localhost:8080/auth/naver/callback");
        //params.add("code", code);
        params.add("grant_type", "authorization_code");
        params.add("client_id", client_id);
        params.add("redirect_uri", "http://localhost:8080/auth/"+social+"/callback");
        params.add("client_secret", client_secret);
        params.add("code", code);

        //HttpHeader와 HttpBody를 하나의 오브젝트에 담기
        HttpEntity<MultiValueMap<String, String>> socialTokenRequest =
                new HttpEntity<>(params,headers);

        // Http 요청하기 - Post 방식으로 - 그리고 response 응답 받음
        ResponseEntity<String> response = rt.exchange(
                access_token_uri,
                HttpMethod.POST,
                socialTokenRequest,
                String.class
        );

        // Gson, Json Simple, ObjectMapper
        ObjectMapper obMapper = new ObjectMapper();
        OAuthToken oauthToken = null;

        try {
            oauthToken = obMapper.readValue(response.getBody(), OAuthToken.class);
        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        System.out.println("소셜 엑세스 토큰 : "+oauthToken.getAccess_token());

        RestTemplate rt2 = new RestTemplate();

        //HttpHeader 오브젝트 생성
        HttpHeaders headers2 = new HttpHeaders();
        headers2.add("Authorization", "Bearer "+oauthToken.getAccess_token());
        headers2.add("Content-type", "application/x-www-form-urlencoded;charset=utf-8");

        //HttpHeader와 HttpBody를 하나의 오브젝트에 담기
        HttpEntity<MultiValueMap<String, String>>socialProfileRequest2 =
                new HttpEntity<>(headers2);

        // Http 요청하기 - Pos t 방식으로 - 그리고 response 응답 받음
        ResponseEntity<String> response2 = rt2.exchange(
                //"https://kapi.kakao.com/v2/user/me",
                api_uri,
                HttpMethod.POST,
                socialProfileRequest2,
                String.class
        );

        ObjectMapper obMapper2 = new ObjectMapper();
        Object socialProfile = null;

        KakaoProfile kakao_Profile = null;
        NaverProfile naver_Profile = null;
        GoogleProfile google_Profile = null;
        try {
            if(social.equals("kakao")){
                kakao_Profile = obMapper2.readValue(response2.getBody(), KakaoProfile.class);
            }else if(social.equals("naver")){
                naver_Profile = obMapper2.readValue(response2.getBody(), NaverProfile.class);
            }else if(social.equals("google")){
                google_Profile = obMapper2.readValue(response2.getBody(), GoogleProfile.class);
            }

        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }

        //System.out.println("socialProfile.getEmail() ::: "+socialProfile.getEmail());

        String username = "";
        String email = "";
        switch (social){
            case "kakao":
                username = kakao_Profile.getKakao_account().getEmail()+"_Kakao";
                email = kakao_Profile.getKakao_account().getEmail();
                break;
            case "naver":
                username = naver_Profile.getResponse().getEmail()+"_Naevr";
                email = naver_Profile.getResponse().getEmail();
                break;
            case "google":
                username = google_Profile.getEmail()+"_Google";
                email = google_Profile.getEmail();
                break;
        }


        //String username = socialProfile.response.getEmail()+"_Naver";
        //UUID garbagePassword = UUID.randomUUID();

        User naverUser = User.builder()
                .username(username)
                .password(cosKey)
                .email(email)
                .oauth(social)
                .build();


        UserDto.Save userDto = new UserDto.Save();
        userDto.setUserId(username);
        userDto.setPassword(cosKey);
        userDto.setOauth(social);
        userDto.setEmail(email);

        User originUser = userService.getUser(username);
        if(originUser.getUsername() == null) {
            userService.createUser(userDto);
        }
        //로그인 처리
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(naverUser.getUsername(),cosKey));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return "redirect:/";
    }
}
