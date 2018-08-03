package io.github.akoserwal.keycloakjwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.BadJWSException;
import com.nimbusds.jwt.proc.BadJWTException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("Access Token Validator")
@ExtendWith(MockitoExtension.class)
class KeycloakTokenValidatorTest {

    final static String jwksetUrl = "http://localhost:8081/auth/realms/test/protocol/openid-connect/certs";
    final static String resource="test_resource";
    final static String jwt_username_claim="preferred_username";
    final static String username= "akoserwal";
    final static String firstname ="abhishek";
    final static String lastname ="koserwal";

    KeycloakTokenValidator KeycloakTokenValidator;


    private TokenGenerator tokenUtil;


    @BeforeEach
    void setUp() throws Exception{
        // initialize a JWT web token with asymmetric RS256 encryption
        tokenUtil   =  new TokenGenerator(JWSAlgorithm.RS256);

    }

    @Test
    @DisplayName("Testing Builder")
    void test_tokenBuilder() {
        KeycloakTokenValidator = KeycloakTokenValidator.builder()
                .connectTimeout(400).readTimeout(400).build(jwksetUrl, resource, jwt_username_claim);

        assertNotNull(KeycloakTokenValidator);
    }

    @Test
    void test_tokenValidator() throws Exception{

        KeycloakTokenValidator = KeycloakTokenValidator.builder().jwtProcessor(tokenUtil.getJwtProcessor()).build(jwksetUrl, resource, jwt_username_claim);

        String token = tokenUtil.getTestToken(resource, username, firstname, lastname);

        String username =  KeycloakTokenValidator.validate(token);
        assertEquals("akoserwal", username);

    }

    @Test
    void test_exceptionInvalidResourceName() throws Exception {

        Throwable exception = assertThrows(BadJWTException.class, () -> {
            throw new BadJWTException("Invalid Keycloak Resource!");
        });

        KeycloakTokenValidator = KeycloakTokenValidator.builder().jwtProcessor(tokenUtil.getJwtProcessor()).build(jwksetUrl, resource, jwt_username_claim);
        String token = tokenUtil.getTestToken("testclient",  username, firstname, lastname);

        KeycloakTokenValidator.validate(token);

        assertEquals("Invalid Keycloak Resource!", exception.getMessage());
    }



    @Test
    void test_exceptionInvalidAccesstoken() throws Exception {

        KeycloakTokenValidator = KeycloakTokenValidator.builder()
                .build(jwksetUrl, resource, jwt_username_claim);

        String token = tokenUtil.getTestToken(resource,  username, firstname, lastname);
        Assertions.assertThrows(BadJWSException.class, () -> KeycloakTokenValidator.validate(token), "Signed JWT rejected: Invalid signature");
    }


}