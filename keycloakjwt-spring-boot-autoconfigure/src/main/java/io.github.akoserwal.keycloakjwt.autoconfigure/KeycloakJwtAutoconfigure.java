package io.github.akoserwal.keycloakjwt.autoconfigure;

import io.github.akoserwal.keycloakjwt.KeycloakTokenFilter;
import io.github.akoserwal.keycloakjwt.KeycloakTokenValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;

/**
 * @author akoserwa@redhat.com
 */

public class KeycloakJwtAutoconfigure {

    @Autowired
    private KeycloakJwtProperties properties;


    @Bean
    public KeycloakTokenFilter keycloaktokenFilterBean() throws Exception {
        return new KeycloakTokenFilter( KeycloakTokenValidator.builder()
                .readTimeout(properties.getReadTimeoutms())
                .connectTimeout(properties.getConnectTimeoutms())
                .sizeLimit(properties.getSizeLimit())
                .build(properties.getJwkUrl(), properties.getResource(), properties.getJwtClaim()));
    }
}
