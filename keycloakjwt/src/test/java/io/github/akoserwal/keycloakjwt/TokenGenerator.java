package io.github.akoserwal.keycloakjwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.RandomStringUtils;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.Date;
import java.util.UUID;

public class TokenGenerator {
    private final JWSAlgorithm algorithm;
    private final RSAPublicKey publicKey;
    private final PrivateKey privateKey;
    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private final int tokenLifeTime;

    public TokenGenerator(JWSAlgorithm algorithm, int tokenLifeTime) throws NoSuchAlgorithmException {
        this.algorithm = algorithm;
        this.tokenLifeTime = tokenLifeTime;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

        int keySize = 2048;
        keyPairGenerator.initialize(keySize);

        KeyPair keyPair = keyPairGenerator.genKeyPair();
        publicKey = (RSAPublicKey) keyPair.getPublic();
        privateKey = keyPair.getPrivate();

        String keyId = RandomStringUtils.randomNumeric(32);

        // Create a JSON Web Key that represents a cryptographic key
        JWK jwk = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .algorithm(algorithm)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .build();

        // Create a JWK set that contains an array of JSON Web Keys
        JWKSet jwkSet = new JWKSet(jwk);

        // Set up a JWT processor to parse the tokens and then check their signature
        // and validity time window
        jwtProcessor = new DefaultJWTProcessor<SecurityContext>();
        JWKSource<SecurityContext> keySource = new ImmutableJWKSet<SecurityContext>(jwkSet);
        JWSKeySelector keySelector = new JWSVerificationKeySelector(algorithm, keySource);
        this.jwtProcessor.setJWSKeySelector(keySelector);

    }

    public TokenGenerator(JWSAlgorithm algorithm) throws NoSuchAlgorithmException {
        this(algorithm, 15);
    }


    /**
     * returns a JWTProcessor for parsing and processing signed and encrypted JSON Web Tokens.
     *
     * @return the initialized JWTProcessor with the JWK set.
     */
    public ConfigurableJWTProcessor getJwtProcessor() {
        return jwtProcessor;
    }


    /**
     * returns a JWT Web Token
     *
     * @param client The client ID
     * @param userName The user name
     * @param firstName The first name
     * @param lastName The last name
     *
     * @return the encoded JWT Web Token
     * @throws Exception
     */
    public String getTestToken(String client, String userName, String firstName, String lastName) throws Exception {

        Date expirationTime = Date.from(ZonedDateTime.now(ZoneOffset.UTC).plusMinutes(tokenLifeTime).toInstant());

        JWSSigner jwsSigner = new RSASSASigner(privateKey);
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .jwtID(UUID.randomUUID().toString())
                .audience(client)
                .issuer("unit test")
                .issueTime(new Date())
                .expirationTime(expirationTime)
                .claim("LOGIN", userName)
                .claim("preferred_username", userName)
                .claim("username", userName)
                .claim("firstName", firstName)
                .claim("lastName", lastName)
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(algorithm), claimsSet);
        signedJWT.sign(jwsSigner);

        return signedJWT.serialize();
    }

    /**
     * Encode user name and password for Basic Authentication header
     * @param userName The user name
     * @param password The password
     *
     * @return the encoded basic authentication header
     */
    public static String encodeBasicAuthentication(final String userName, final String password) {
        final String pair = userName + ":" + password;
        final byte[] encodedBytes = Base64.encodeBase64(pair.getBytes());
        return new String(encodedBytes);

    }
}


