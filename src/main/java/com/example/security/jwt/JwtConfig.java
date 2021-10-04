package com.example.security.jwt;

import com.google.common.net.HttpHeaders;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application.jwt")
@Getter
@Setter
@NoArgsConstructor
public class JwtConfig {
    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationDays;

    public String getAuthHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
