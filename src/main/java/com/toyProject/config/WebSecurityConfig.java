package com.toyProject.config;

import com.toyProject.config.auth.PrincipalDetailService;
import com.toyProject.security.AuthFailureHandler;
import com.toyProject.security.AuthSuccessHandler;
import com.toyProject.security.JwtAuthenticationFilter;
import com.toyProject.security.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.context.request.RequestContextListener;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private AuthSuccessHandler authSuccessHandler;

    @Autowired
    private AuthFailureHandler authFailureHandler;

    @Bean
    public RequestContextListener requestContextListener() {
        return new RequestContextListener();
    }
    @Autowired
    private PrincipalDetailService principalDetailService;

    private final JwtTokenProvider jwtTokenProvider;


    AuthenticationDetailsSource authenticationDetailsSource;


    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean	//Ioc가 된다..
    public BCryptPasswordEncoder encodePassword() {
        return new BCryptPasswordEncoder();
    }

    //	시큐리티가 대신 로그인해주는데 password를 가로채기 하는데
    //	해당 password가 뭘로 해쉬가 되어 회원가입이 되었는지 알아야
    //	같은 해쉬로 암호화해서 DB에 있는 해쉬랑 비교할 수 있음.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(principalDetailService).passwordEncoder(encodePassword());
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        //super.configure(web);
        //web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/static/**", "/streaming/**","/assets/**","/sass/**");
        /*web.ignoring().antMatchers("/css/**");
        web.ignoring().antMatchers("/scripts/**");
        web.ignoring().antMatchers("/img/**");
        web.ignoring().antMatchers("/static/**");
        web.ignoring().antMatchers("/assets/**");
        web.ignoring().antMatchers("/js/**");*/
        //web.httpFirewall(allowUrlEncodedSlashHttpFirewall());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.cors().disable().csrf().ignoringAntMatchers("/auth/loginForm");

        http.headers().frameOptions().disable();
        http.headers().httpStrictTransportSecurity().disable();
        http.requiresChannel().anyRequest().requiresInsecure();


        http
                //.csrf().disable()
                .authorizeRequests()
                .antMatchers("/","/auth/**","/js/**","/css/**","/assets/**","/img/**")	//auth 등 들어오는건 누구나 들어올수 있다.
                .permitAll()
                .anyRequest().authenticated()   //인증이 되어야 한다.
                .and()
                //jwt 토큰을 여기서 검사후 토큰 인증이 되면 Oauth검사하지 않고 바로 로그인 시켜준다.
                .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class) // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 넣는다
                    .formLogin()//Form 로그인 인증 기능이 작동함
                    .loginPage("/auth/loginForm")//사용자 정의 로그인 페이지
                    //.defaultSuccessUrl("/")//로그인 성공 후 이동 페이지
                    //.failureUrl("/login.html?error=true")// 로그인 실패 후 이동 페이지
                    .usernameParameter("username")//아이디 파라미터명 설정
                    .passwordParameter("password")//패스워드 파라미터명 설정
                    .authenticationDetailsSource(authenticationDetailsSource)
                    .loginProcessingUrl("/login")//로그인 Form Action Url
                    .successHandler(authSuccessHandler)//로그인 성공 후 핸들러 (해당 핸들러를 생성하여 핸들링 해준다.), jwt토큰 인증이 안되면 여기서 다시 검사함
                    .failureHandler(authFailureHandler); //로그인 실패 후 핸들러 (해당 핸들러를 생성하여 핸들링 해준다.)

        // + 토큰에 저장된 유저정보를 활용하여야 하기 때문에 CustomUserDetailService 클래스를 생성합니다.
        //http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS); //사용자 정의 로그인 페이지 접근 권한 승인

        http.logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .deleteCookies("JSESSIONID","toy-remember-me")
                .clearAuthentication(true)
                .invalidateHttpSession(true)
                .logoutSuccessUrl("/");
    }

    @Bean
    public HttpFirewall allowUrlEncodedSlashHttpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowUrlEncodedSlash(true);
        firewall.setAllowSemicolon(true);
        return firewall;
    }

}
