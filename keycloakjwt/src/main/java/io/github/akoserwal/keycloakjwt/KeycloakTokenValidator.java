package io.github.akoserwal.keycloakjwt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.RemoteKeySourceException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.BadJWTException;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.List;

/**
 * @author akoserwa@redhat.com
 */

public class KeycloakTokenValidator  {


    private static final Log log = LogFactory.getLog(KeycloakTokenValidator.class);


    public static final String JWT_AUD = "aud";

    /**
     * keycloak certs url
     */
    private String jwkUrl;

    /**
     *Client ID
     */
    private String resource;

    /**
     * @param jwtClaim: defined in keycloak mapper for client id: preferred_username or username
     */
    private String jwtClaim;


    /**
     * Creates a new resource retriever.
     *
     * @param connectTimeoutms The HTTP connects timeout, in milliseconds,
     *                       zero for infinite. Must not be negative.
     * @param readTimeoutms    The HTTP read timeout, in milliseconds, zero
     *                       for infinite. Must not be negative.
     * @param sizeLimit      The HTTP entity size limit, in bytes, zero for
     *                       infinite. Must not be negative.
     */

    private int connectTimeoutms = 0;
    private int readTimeoutms = 0;
    private int sizeLimit= 0;

    public void setJwtProcessor(ConfigurableJWTProcessor jwtProcessor) {
        this.jwtProcessor = jwtProcessor;
    }

    private ConfigurableJWTProcessor jwtProcessor;

    private JWSKeySelector keySelector(JWKSource keySource) {
        return new JWSVerificationKeySelector(JWSAlgorithm.RS256, keySource);
    }


    private void init(String jwkUrl) {
        if (jwkUrl!=null) {
            log.info("Initializing JWK set from " + jwkUrl);
            try {
                JWKSet jwkSet = getJwkSet(jwkUrl);
                JWKSource keySource = new ImmutableJWKSet(jwkSet);
                jwtProcessor.setJWSKeySelector(keySelector(keySource));
                log.info("JWK set initialized successfully.");
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }


    public JWKSet getJwkSet(String jwkUrl) throws IOException, ParseException {
        return JWKSet.load(new URL(jwkUrl), connectTimeoutms, readTimeoutms, sizeLimit);
    }

    public String validate(String accessToken) throws BadJOSEException {

        SecurityContext ctx = null;
        try {
            JWTClaimsSet claimsSet = getJwtClaimsSet(accessToken, ctx);
            if(claimsSet != null) {

                List<String> aud = claimsSet.getAudience();
                if(aud==null || !aud.contains(resource)) {
                    throw new BadJWTException("Invalid Keycloak Resource!");
                }
                return claimsSet.getStringClaim(jwtClaim);
            }

        }catch (RemoteKeySourceException e){
            log.error(e.getMessage());
        }catch (BadJWTException e) {
            log.warn(e.getLocalizedMessage());
        } catch (ParseException | JOSEException e ) {
            log.error(e.getStackTrace());
        }
        return null;
    }

    private JWTClaimsSet getJwtClaimsSet(String accessToken, SecurityContext ctx) throws ParseException, BadJOSEException, JOSEException {
        return jwtProcessor.process(accessToken, ctx);
    }


    // Fluent API Builder
    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder{
        KeycloakTokenValidator accessTokenValidator;

        private Builder() {
            accessTokenValidator = new KeycloakTokenValidator();
        }


        public Builder connectTimeout(final int connectTimeout) {
            accessTokenValidator.connectTimeoutms = connectTimeout;
            return this;
        }

        public Builder readTimeout(final int readTimeout) {
            accessTokenValidator.readTimeoutms = readTimeout;
            return this;
        }

        public Builder sizeLimit(final int sizeLimit) {
            accessTokenValidator.sizeLimit = sizeLimit;
            return this;
        }

        public Builder jwtProcessor(ConfigurableJWTProcessor jwtProcessor) {
            accessTokenValidator.jwtProcessor = jwtProcessor;
            return this;
        }


        public KeycloakTokenValidator build(final String jwksetUrl,final String resource,final String jwt_username_claim){
            accessTokenValidator.resource = resource;
            accessTokenValidator.jwtClaim = jwt_username_claim;
            accessTokenValidator.jwkUrl = jwksetUrl;

            if(accessTokenValidator.jwtProcessor == null)
            {
                accessTokenValidator.jwtProcessor = new DefaultJWTProcessor();
                accessTokenValidator.init(jwksetUrl);
            }

            return accessTokenValidator;
        }

    }
}
