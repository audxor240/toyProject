package com.toyProject.properties;

import lombok.Data;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties("app")
public class AppProperties {

    private String name;
    private String title;
    private String emailAddress;
    private String host;

    private String googleClientId;
    private String googleClientSecret;
    private String googleRequestTokenUri;
    private String googleAccessTokenUri;
    private String googleApiUri;

    private String naverClientId;
    private String naverClientSecret;
    private String naverRequestTokenUri;
    private String naverAccessTokenUri;
    private String naverApiUri;

    private String kakaoClientId;
    private String kakaoRequestTokenUri;
    private String kakaoAccessTokenUri;
    private String kakaoApiUri;

    private String iamportKey;
    private String iamportSecret;

    private String jwtSecret;
    private String jwtLimit;

    private String geotoolsSld;
}
