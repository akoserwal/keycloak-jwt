package io.github.akoserwal.keycloakjwt;

import com.nimbusds.jose.JWSAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.when;

@DisplayName("Auth Token Filter")
@ExtendWith(MockitoExtension.class)
class KeycloakTokenFilterTest {

    final static String jwksetUrl = "http://localhost:8081/auth/realms/test/protocol/openid-connect/certs";
    final static String resource="test_resource";
    final static String jwt_username_claim="preferred_username";
    final static String username= "akoserwal";
    final static String firstname ="abhishek";
    final static String lastname ="koserwal";

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    HttpServletResponse httpServletResponse;

    @Mock
    FilterChain chain;

    KeycloakTokenValidator tokenValidator;

    private TokenGenerator tokenGen;

    private final static String authorizationHeader = "Authorization";
    private static final String BEARER = "Bearer ";


    @BeforeEach
    void setUp() throws Exception {

        tokenGen = new TokenGenerator(JWSAlgorithm.RS256);

    }

    @Test
    void test_doFilterInternal() throws Exception {
        String token = tokenGen.getTestToken(resource, username, firstname,lastname);

        when(httpServletRequest.getHeader(authorizationHeader)).thenReturn(BEARER+ token);
        tokenValidator = KeycloakTokenValidator.builder().jwtProcessor(tokenGen.getJwtProcessor()).build(jwksetUrl, resource, jwt_username_claim);


        KeycloakTokenFilter tokenFilter = new KeycloakTokenFilter(tokenValidator);
        tokenFilter.doFilterInternal(httpServletRequest,httpServletResponse, chain);

    }


}