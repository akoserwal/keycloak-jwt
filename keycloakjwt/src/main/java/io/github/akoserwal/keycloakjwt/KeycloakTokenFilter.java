package io.github.akoserwal.keycloakjwt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @author akoserwa@redhat.com
 */
public class KeycloakTokenFilter extends OncePerRequestFilter {

    private static final Log log = LogFactory.getLog(KeycloakTokenFilter.class);

    private static final String BEARER = "Bearer ";
    private final static String authorizationHeader = "Authorization";
    private KeycloakTokenValidator tokenValidator;
    private String username;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        String token = request.getHeader(authorizationHeader);

        if (token!=null && !token.toUpperCase().startsWith("BASIC")) {
            try {

                if (token.length() > BEARER.length() && token.startsWith(BEARER)) {
                    token = token.substring(BEARER.length());
                }

                username = tokenValidator.validate(token);

                log.info("username:"+username);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    setContext(request, username);

                } else {
                    log.info("Invalid Request: Token is expired or tampered");
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized: Token is expired or tampered");
                }
            } catch (Exception e) {
                log.error(e);

            }

        } else {
            log.info("Authorization Token not being sent in Headers:"+token);
        }

        filterChain.doFilter(request, response);
    }

    private void setContext(HttpServletRequest request, String username) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(username, null, null);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        log.debug("authenticated user " + username + ", setting security context");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setAttribute("username", username);
    }

    public KeycloakTokenFilter(KeycloakTokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}
