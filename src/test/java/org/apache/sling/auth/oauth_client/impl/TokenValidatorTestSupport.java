/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.osgi.util.converter.Converters;

/**
 * Shared test utilities for token validator tests.
 * Provides common functionality for creating mock connections, tokens, and servers.
 */
class TokenValidatorTestSupport {

    static final String ISSUER = "https://test-issuer.example.com";
    static final String SUBJECT = "test-subject";
    static final String CLIENT_ID = "test-client-id";
    static final String DEFAULT_AUDIENCE = "test-audience";
    static final String DEFAULT_SCOPE = "openid profile";

    private RSAKey rsaKey;
    private JWSSigner signer;

    TokenValidatorTestSupport() throws JOSEException {
        rsaKey = new RSAKeyGenerator(2048).keyID("test-key-id").generate();
        signer = new RSASSASigner(rsaKey);
    }

    RSAKey getRsaKey() {
        return rsaKey;
    }

    JWSSigner getSigner() {
        return signer;
    }

    /**
     * Creates a JWK server that serves the public key.
     */
    HttpServer createJwkServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(0), 0);
        server.createContext("/.well-known/jwks.json", exchange -> {
            JWKSet jwkSet = new JWKSet(rsaKey.toPublicJWK());
            String response = jwkSet.toString();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, response.getBytes().length);
            exchange.getResponseBody().write(response.getBytes());
            exchange.getResponseBody().close();
        });
        server.start();
        return server;
    }

    /**
     * Creates a mock OIDC connection with the given JWK server port.
     */
    OidcConnectionImpl createConnection(int jwkServerPort) {
        return createConnection(jwkServerPort, null);
    }

    /**
     * Creates a mock OIDC connection with the given JWK server port and optional introspection endpoint.
     */
    OidcConnectionImpl createConnection(int jwkServerPort, String introspectionEndpoint) {
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("name", "test-connection");
        configMap.put("baseUrl", "");
        configMap.put("authorizationEndpoint", "http://localhost/auth");
        configMap.put("tokenEndpoint", "http://localhost/token");
        configMap.put("userInfoUrl", "http://localhost/userinfo");
        configMap.put("jwkSetURL", "http://localhost:" + jwkServerPort + "/.well-known/jwks.json");
        configMap.put("issuer", ISSUER);
        configMap.put("introspectionEndpoint", introspectionEndpoint != null ? introspectionEndpoint : "");
        configMap.put("clientId", CLIENT_ID);
        configMap.put("clientSecret", "secret");
        configMap.put("scopes", new String[] {"openid"});
        configMap.put("additionalAuthorizationParameters", new String[0]);

        return new OidcConnectionImpl(
                Converters.standardConverter().convert(configMap).to(OidcConnectionImpl.Config.class), null);
    }

    /**
     * Creates a valid signed JWT token.
     */
    String createValidToken() throws JOSEException {
        return createToken(SUBJECT, ISSUER, new Date(System.currentTimeMillis() + 3600000));
    }

    /**
     * Creates a signed JWT token with the given parameters.
     */
    String createToken(String subject, String issuer, Date expiration) throws JOSEException {
        return createToken(subject, issuer, expiration, CLIENT_ID, DEFAULT_SCOPE, DEFAULT_AUDIENCE);
    }

    /**
     * Creates a signed JWT token with full customization.
     */
    String createToken(String subject, String issuer, Date expiration, String clientId, String scope, String audience)
            throws JOSEException {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .expirationTime(expiration)
                .issueTime(new Date());

        if (audience != null) {
            builder.audience(audience);
        }
        if (clientId != null) {
            builder.claim("client_id", clientId);
        }
        if (scope != null) {
            builder.claim("scope", scope);
        }

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(rsaKey.getKeyID())
                        .build(),
                builder.build());
        signedJWT.sign(signer);

        return signedJWT.serialize();
    }

    /**
     * Creates a signed JWT token with custom claims.
     */
    String createTokenWithClaims(JWTClaimsSet claimsSet) throws JOSEException {
        return createTokenWithClaims(claimsSet, rsaKey.getKeyID());
    }

    /**
     * Creates a signed JWT token with custom claims and key ID.
     */
    String createTokenWithClaims(JWTClaimsSet claimsSet, String keyId) throws JOSEException {
        JWSHeader.Builder headerBuilder = new JWSHeader.Builder(JWSAlgorithm.RS256);
        if (keyId != null) {
            headerBuilder.keyID(keyId);
        }
        SignedJWT signedJWT = new SignedJWT(headerBuilder.build(), claimsSet);
        signedJWT.sign(signer);
        return signedJWT.serialize();
    }

    /**
     * Creates an OfflineTokenValidator config.
     */
    static OfflineTokenValidator.Config createOfflineConfig(
            String name, String[] acceptedClientIds, String[] requiredScopes, String[] requiredAudiences) {
        return createOfflineConfig(name, acceptedClientIds, requiredScopes, requiredAudiences, null, 60, 300);
    }

    /**
     * Creates an OfflineTokenValidator config with full customization.
     */
    static OfflineTokenValidator.Config createOfflineConfig(
            String name,
            String[] acceptedClientIds,
            String[] requiredScopes,
            String[] requiredAudiences,
            String[] allowedAlgorithms,
            long clockSkewSeconds,
            long jwkCacheTtlSeconds) {
        Map<String, Object> configMap = createConfigMap(name, acceptedClientIds, requiredScopes, requiredAudiences);
        if (allowedAlgorithms != null) {
            configMap.put("allowedAlgorithms", allowedAlgorithms);
        }
        configMap.put("clockSkewSeconds", clockSkewSeconds);
        configMap.put("jwkCacheTtlSeconds", jwkCacheTtlSeconds);
        return Converters.standardConverter().convert(configMap).to(OfflineTokenValidator.Config.class);
    }

    /**
     * Creates an OnlineTokenValidator config.
     */
    static OnlineTokenValidator.Config createOnlineConfig(
            String name, String[] acceptedClientIds, String[] requiredScopes, String[] requiredAudiences) {
        return Converters.standardConverter()
                .convert(createConfigMap(name, acceptedClientIds, requiredScopes, requiredAudiences))
                .to(OnlineTokenValidator.Config.class);
    }

    private static Map<String, Object> createConfigMap(
            String name, String[] acceptedClientIds, String[] requiredScopes, String[] requiredAudiences) {
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("name", name);
        configMap.put("acceptedClientIds", acceptedClientIds != null ? acceptedClientIds : new String[0]);
        configMap.put("requiredScopes", requiredScopes != null ? requiredScopes : new String[0]);
        configMap.put("requiredAudiences", requiredAudiences != null ? requiredAudiences : new String[0]);
        return configMap;
    }
}
