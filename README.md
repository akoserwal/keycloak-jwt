# Keycloak JWT Token Validator Library #


 Library parse & validate keycloak jwt token as security filter in spring/spring-boot application.


Add to pom for spring-framework project

```
    <dependency>
        <groupId>io.github.akoserwal</groupId>
	    <artifactId>keycloakjwt</artifactId>
	    <version>${version}</version>
	</dependency>
```

Add to pom for spring-boot project

```

       <dependency>
            <groupId>io.github.akoserwal</groupId>
            <artifactId>keycloakjwt-spring-boot-starter</artifactId>
            <version>${version}</version>
        </dependency>

```

## Build 

``` mvn install ```



### Spring Application

example:

properties

```
keycloak.key-set-uri=http://localhost:8081/auth/realms/test/protocol/openid-connect/certs
keycloak.resource=test_resource
keycloak.claim=preferred_username
```


 Example: Inject the jwt filer into SecurityConfiguration.

 ```
    @Value("${keycloak.key-set-uri}")
    String jwkUrl;

    @Value("${keycloak.resource}")
    String resource;

    @Value("${keycloak.claim}")
    String jwtClaim;



    @Bean
    public KeycloakTokenFilter keycloakTokenFilterBean() throws Exception {
        return new KeycloakTokenFilter( KeycloakTokenValidator.builder()
                .build(jwkUrl, resource, jwtClaim));
    }
```



### Spring Boot Application

application.properties

```
keycloakjwt.jwk-url=http://localhost:8081/auth/realms/test/protocol/openid-connect/certs
keycloakjwt.resource=perf-devep-test
keycloakjwt.jwt-claim=preferred_username
keycloakjwt.connect-timeoutms=500 //optional
keycloakjwt.read-timeoutms=500 // optional

```


Add to security config class

```
    @Autowired
    KeycloakTokenFilter keycloakTokenFilter;


   // and filter

      .addFilterBefore(keycloakTokenFilter, UsernamePasswordAuthenticationFilter.class)

```


License
-------

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)



