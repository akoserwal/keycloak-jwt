package io.github.akoserwal.keycloakjwt.autoconfigure;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * @author akoserwa@redhat.com
 */

@ConfigurationProperties("keycloakjwt")
public class KeycloakJwtProperties {


    /**
     * @param jwkUrl: keycloak certs jwkUrl
     */
    private String jwkUrl;

    /**
     * @param:resource: Client ID configured in keycloak
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


    public String getJwkUrl() {
        return jwkUrl;
    }

    public void setJwkUrl(String jwkUrl) {
        this.jwkUrl = jwkUrl;
    }

    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    public String getJwtClaim() {
        return jwtClaim;
    }

    public void setJwtClaim(String jwtClaim) {
        this.jwtClaim = jwtClaim;
    }

    public int getConnectTimeoutms() {
        return connectTimeoutms;
    }

    public void setConnectTimeoutms(int connectTimeoutms) {
        this.connectTimeoutms = connectTimeoutms;
    }

    public int getReadTimeoutms() {
        return readTimeoutms;
    }

    public void setReadTimeoutms(int readTimeoutms) {
        this.readTimeoutms = readTimeoutms;
    }

    public int getSizeLimit() {
        return sizeLimit;
    }

    public void setSizeLimit(int sizeLimit) {
        this.sizeLimit = sizeLimit;
    }

}
