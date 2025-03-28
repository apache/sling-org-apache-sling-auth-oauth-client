/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.LoginCookieManager;
import org.apache.sling.jcr.api.SlingRepository;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Component(
        service = AuthenticationHandler.class,
        immediate = true
)

@Designate(ocd = OidcBearerTokenAuthenticationHandler.Config.class, factory = true)
public class OidcBearerTokenAuthenticationHandler extends DefaultAuthenticationFeedbackHandler implements AuthenticationHandler {

    private final Map<String, ClientConnection> connections;
    private String defaultConnectionName;
    private String idp = "oidc";
    private String cookieName;
    private String wellKnownUrl;

    @ObjectClassDefinition(
            name = "Apache Sling Oidc Bearer Authentication Handler",
            description = "Apache Sling Oidc Bearer Authentication Handler Service"
    )

    @interface Config {
        @AttributeDefinition(name = "Path",
                description = "Repository path for which this authentication handler should be used by Sling. If this is " +
                        "empty, the authentication handler will be disabled. By default this is set to \"/\".")
        String path() default "/";

        @AttributeDefinition(name = "CookieName",
                description = "The name of the Cookie to read the token from. When empty, the Authorization header is used.")
        String cookieName() default "";

        @AttributeDefinition(name = "idp",
                description = "The IDP name to use for the authentication handler.")
        String idp() default "oidc";

        @AttributeDefinition(name = "Default Connection Name",
                description = "The name of the default connection to use for the authentication handler.")
        String defaultConnectionName() default "";

        @AttributeDefinition(name = "Well-Known URL",
                description = "The URL of the well-known configuration file for the OIDC provider.")
        String well_known_url();
    }

    @Activate
    public OidcBearerTokenAuthenticationHandler(@Reference(policyOption = ReferencePolicyOption.GREEDY) @NotNull SlingRepository repository,
                                                @NotNull BundleContext bundleContext, @Reference List<ClientConnection> connections,
                                                OidcBearerTokenAuthenticationHandler.Config config,
                                                @Reference(cardinality = ReferenceCardinality.OPTIONAL) LoginCookieManager loginCookieManager) {
        this.connections = connections.stream()
                .collect(Collectors.toMap( ClientConnection::name, Function.identity()));
        this.idp = config.idp();
        this.cookieName = config.cookieName();
        this.defaultConnectionName = config.defaultConnectionName();
        this.wellKnownUrl = config.well_known_url();

    }
        @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {

        // The access token to validate, typically submitted with an HTTP header like
        String accessToken;
        if (cookieName != null && !cookieName.isEmpty()) {
            accessToken = httpServletRequest.getHeader("Authorization");
            if (accessToken == null) {
                accessToken = Arrays.stream(httpServletRequest.getCookies())
                        .filter(c -> cookieName.equals(c.getName()))
                        .map(c -> c.getValue())
                        .findFirst()
                        .orElse(null);
            }
        } else {
            accessToken = httpServletRequest.getHeader("Authorization");
        }

        // Create a JWT processor for the access tokens
        ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();

        // Set the required "typ" header "at+jwt" for access tokens
        jwtProcessor.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("at+jwt")));

        // The public RSA keys to validate the signatures will be sourced from the
        // OAuth 2.0 server's JWK set URL. The key source will cache the retrieved
        // keys for 5 minutes. 30 seconds prior to the cache's expiration the JWK
        // set will be refreshed from the URL on a separate dedicated thread.
        // Retrial is added to mitigate transient network errors.
        JWKSource<SecurityContext> keySource = null;
        try {
            keySource = JWKSourceBuilder
                    .create(new URL(this.wellKnownUrl))
                    .retrying(true)
                    .build();
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }

        // The expected JWS algorithm of the access tokens (agreed out-of-band)
        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        // Configure the JWT processor with a key selector to feed matching public
        // RSA keys sourced from the JWK set URL
        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                expectedJWSAlg,
                keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        // Set the required JWT claims for access tokens
        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer("https://demo.c2id.com").build(),
                new HashSet<>(Arrays.asList(
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        "scp",
                        "cid",
                        JWTClaimNames.JWT_ID))));

        // Process the token
        SecurityContext ctx = null; // optional context parameter, not required here
        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(accessToken, ctx);
        } catch (ParseException | BadJOSEException e) {
            // Invalid token
            System.err.println(e.getMessage());
            return AuthenticationInfo.FAIL_AUTH;
        } catch (JOSEException e) {
            // Key sourcing failed or another internal exception
            System.err.println(e.getMessage());
            return AuthenticationInfo.FAIL_AUTH;
        }


        // TODO
        return AuthenticationInfo.FAIL_AUTH;
    }

    @Override
    public boolean requestCredentials(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        // TODO
        return false;
    }

    @Override
    public void dropCredentials(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws IOException {
        // TODO

    }
}
