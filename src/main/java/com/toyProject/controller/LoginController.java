package com.toyProject.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.toyProject.common.HttpClient;
import com.toyProject.common.HttpResult;
import com.toyProject.dto.UserDto;
import com.toyProject.model.*;
import com.toyProject.properties.AppProperties;
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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
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

    @GetMapping("/auth/loginForm")
    public String loginForm(Model model, HttpServletRequest request){

        socialLoginSupport.setSocialOauthUrl(request, model);
        System.out.println("loginForm!!!!!!!");
        return "/pages/loginForm";
    }

    /*@GetMapping("/auth/naver/callback")
    public String loginByNaver(@RequestParam("code") String token, @RequestParam("state") String state
            , HttpServletRequest request, HttpServletResponse response, RedirectAttributes redirectAttributes) throws UnsupportedEncodingException {
        String clientId = appProperties.getNaverClientId();
        String clientSecret = appProperties.getNaverClientSecret();
        String redirectUri = appProperties.getHost() + "/login/naver";
        System.out.println(":::state:::" + state);

        HttpResult result = HttpClient.post(appProperties.getNaverAccessTokenUri(),
                "grant_type=authorization_code&client_id=" + clientId + "&client_secret=" + clientSecret +
                        "&code=" + token + "&state=" + state);
        JSONObject tokenObject = JSONObject.fromObject(result.getData());

        String authKey = "Bearer ";
        try {
            authKey += tokenObject.getString("access_token");
        } catch (JSONException e) {
            return "redirect:"+appProperties.getHost();
        }

        HttpResult objects = HttpClient.getWithAuthorize(appProperties.getNaverApiUri(), authKey);

        JSONObject resultObject = JSONObject.fromObject(objects.getData()).getJSONObject("response");

        System.out.println("resultObject :: "+resultObject);

        String uniqueId = resultObject.getString("id");
        String email = resultObject.getString("email");

        String name = URLEncoder.encode(resultObject.getString("name"), "UTF-8");

        User user = userService.getUserAsEmail(email+"_Naver");

        if(user == null){


            *//*String username = socialProfile.getEmail()+"_Naver";
            //UUID garbagePassword = UUID.randomUUID();
            User naverUser = User.builder()
                    .username(username)
                    .password(cosKey)
                    .email(socialProfile.getEmail())
                    .oauth("naver")
                    .build();

            UserDto.Save userDto = new UserDto.Save();
            userDto.setUserId(username);
            userDto.setPassword(cosKey);
            userDto.setEmail(socialProfile.getEmail());*//*

            //return "redirect:"+appProperties.getHost()+"/signup/agree?type=NAVER&uniqueId=" + uniqueId + "&email=" + email + "&name=" + name;
            return "redirect:"+appProperties.getHost();
        }else{

            *//*if (state.contains("_true")) {
                String jwtToken = JWT.create()
                        .withExpiresAt(new Date(System.currentTimeMillis() + Integer.parseInt(appProperties.getJwtLimit())))
                        .withClaim("key", user.getId())
                        .sign(Algorithm.HMAC512(appProperties.getJwtSecret()));

                Cookie myCookie = new Cookie("obscure-remember-me", jwtToken);
                myCookie.setPath("/");
                myCookie.setMaxAge(Integer.parseInt(appProperties.getJwtLimit()));  // 7일동안 유효
                response.addCookie(myCookie);
            }*//*

            List<GrantedAuthority> grantedAuthorityList = new ArrayList<>();
            grantedAuthorityList.add(new SimpleGrantedAuthority("ROLE_USER"));
            //user.setAuthorities(grantedAuthorityList);

            //Authentication authentication = new UsernamePasswordAuthenticationToken(user,"thrhdwk1!",user.getAuthorities());
            //SecurityContextHolder.getContext().setAuthentication(authentication);

            //request.getSession().setAttribute(GlobalConstant.SESSION_USER_KEY, user);   //세션에 저장
            response.setStatus(HttpServletResponse.SC_OK);

            return "redirect:"+appProperties.getHost();
        }
    }*/

    @GetMapping("/auth/{social}/callback")
    public String naver_callback(String code, @PathVariable String social) {	//@ResponseBody =  DATA를 리턴해주는 컨트롤러 함수

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
        }


        System.out.println("code :: "+code);
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
        System.out.println("naverTokenRequest :: "+socialTokenRequest);
        // Http 요청하기 - Post 방식으로 - 그리고 response 응답 받음
        ResponseEntity<String> response = rt.exchange(
                access_token_uri,
                HttpMethod.POST,
                socialTokenRequest,
                String.class
        );
        System.out.println("access_token_uri :: "+access_token_uri);
        // Gson, Json Simple, ObjectMapper
        ObjectMapper obMapper = new ObjectMapper();
        OAuthToken oauthToken = null;
        System.out.println("response.getBody() :: "+response.getBody());
        try {
            oauthToken = obMapper.readValue(response.getBody(), OAuthToken.class);
        } catch (JsonMappingException e) {
            System.out.println("Error ---------- 1");
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            System.out.println("Error ---------- 2");
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
        System.out.println("socialProfileRequest2 ::: "+socialProfileRequest2);
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
        System.out.println("response2 :: "+response2);
        System.out.println("response2.getBody() :: "+response2.getBody());

        System.out.println("social :: "+social);
        KakaoProfile kakao_Profile = null;
        NaverProfile naver_Profile = null;
        try {
            if(social.equals("kakao")){
                kakao_Profile = obMapper2.readValue(response2.getBody(), KakaoProfile.class);
            }else if(social.equals("naver")){
                naver_Profile = obMapper2.readValue(response2.getBody(), NaverProfile.class);
            }

        } catch (JsonMappingException e) {
            e.printStackTrace();
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        }
        System.out.println("socialProfile :: "+socialProfile);
        //System.out.println("socialProfile.getEmail() ::: "+socialProfile.getEmail());

        String username = "";
        String email = "";
        switch (social){
            case "kakao":
                username = kakao_Profile.getKakao_account().getEmail()+"_Naver";
                email = kakao_Profile.getKakao_account().getEmail();
                break;
            case "naver":
                username = naver_Profile.getResponse().getEmail()+"_Naver";
                email = naver_Profile.getResponse().getEmail();
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
