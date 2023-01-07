package com.toyProject.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.toyProject.config.auth.PrincipalDetail;
import com.toyProject.model.User;
import com.toyProject.properties.AppProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

@Slf4j
@Component
public class AuthSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();
    private RequestCache requestCache = new HttpSessionRequestCache();

    @Autowired
    private AppProperties app;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        log.info("onAuthenticationSuccess!");

        //FormWebAuthenticationDetails form = (FormWebAuthenticationDetails) authentication.getDetails();
        FormWebAuthenticationDetails form = new FormWebAuthenticationDetails(request);
        boolean remember = form.getRemember();

        PrincipalDetail user = (PrincipalDetail) authentication.getPrincipal();
        // session setting
        //request.getSession().setAttribute(GlobalConstant.SESSION_USER_KEY, user);
        if (remember == true) {
            /*String jwtToken = JWT.create()
                    .withExpiresAt(new Date(System.currentTimeMillis() + Integer.parseInt(app.getJwtLimit())))
                    .withClaim("key", user.getId())
                    .sign(Algorithm.HMAC512(app.getJwtSecret()));*/
            String jwtToken = jwtTokenProvider.createToken(user.getUsername(),user.getRols());

            Cookie myCookie = new Cookie("toy-remember-me", jwtToken);
            myCookie.setMaxAge(Integer.parseInt(app.getJwtLimit()));  // 7일동안 유효
            response.addCookie(myCookie);
        }
        response.setStatus(HttpServletResponse.SC_OK);

        resultRedirectStrategy(request, response, authentication);
    }

    protected void resultRedirectStrategy(HttpServletRequest request, HttpServletResponse response,
                                          Authentication authentication) throws IOException, ServletException {
        SavedRequest savedRequest = requestCache.getRequest(request, response);

        if (savedRequest != null) {

            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request, response, targetUrl);
        } else {
            //redirectStrategy.sendRedirect(request, response, app.getHost());
            //String targetUrl = savedRequest.getRedirectUrl();
            //redirectStrategy.sendRedirect(request, response, targetUrl);

            redirectStrategy.sendRedirect(request, response, app.getHost());
        }
    }
}
