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

import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.apache.sling.auth.oauth_client.spi.TokenValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.apache.sling.auth.oauth_client.impl.TokenValidatorTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link OfflineTokenValidator}.
 */
class OfflineTokenValidatorTest {

    private static final String VALIDATOR_NAME = "test-offline-validator";

    private TokenValidatorTestSupport support;
    private HttpServer jwkServer;
    private OidcConnectionImpl connection;

    @BeforeEach
    void setUp() throws Exception {
        support = new TokenValidatorTestSupport();
        jwkServer = support.createJwkServer();
        connection = support.createConnection(jwkServer.getAddress().getPort());
    }

    @AfterEach
    void tearDown() {
        if (jwkServer != null) {
            jwkServer.stop(0);
        }
    }

    // ============ Configuration Tests ============

    @Test
    void testActivation_ValidConfig() {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));
        assertEquals(VALIDATOR_NAME, validator.name());
    }

    @Test
    void testActivation_NullName_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OfflineTokenValidator(createOfflineConfig(null, null, null, null)));
    }

    @Test
    void testActivation_EmptyName_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OfflineTokenValidator(createOfflineConfig("", null, null, null)));
    }

    @Test
    void testActivation_EmptyStringInClientIds_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OfflineTokenValidator(
                        createOfflineConfig(VALIDATOR_NAME, new String[] {"valid-client", ""}, null, null)));
    }

    @Test
    void testActivation_EmptyStringInScopes_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OfflineTokenValidator(
                        createOfflineConfig(VALIDATOR_NAME, null, new String[] {"openid", "  "}, null)));
    }

    @Test
    void testActivation_EmptyStringInAudiences_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OfflineTokenValidator(
                        createOfflineConfig(VALIDATOR_NAME, null, null, new String[] {"audience", ""})));
    }

    // ============ Token Validation Tests ============

    @Test
    void testValidate_ValidToken_ReturnsResult() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        TokenValidator.TokenValidationResult result = validator.validate(support.createValidToken(), connection);

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
        assertNotNull(result.getClaimsSet());
    }

    @Test
    void testValidate_ExpiredToken_ReturnsNull() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        String token = support.createToken(SUBJECT, ISSUER, new Date(System.currentTimeMillis() - 3600000));
        assertNull(validator.validate(token, connection));
    }

    @Test
    void testValidate_WrongIssuer_ReturnsNull() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        String token = support.createToken(
                SUBJECT, "https://wrong-issuer.example.com", new Date(System.currentTimeMillis() + 3600000));
        assertNull(validator.validate(token, connection));
    }

    @Test
    void testValidate_MalformedToken_ReturnsNull() {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));
        assertNull(validator.validate("not.a.valid.jwt", connection));
    }

    @Test
    void testValidate_TokenWithoutSubject_ReturnsNull() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .audience(DEFAULT_AUDIENCE)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .build();

        assertNull(validator.validate(support.createTokenWithClaims(claimsSet), connection));
    }

    @Test
    void testValidate_UnsignedToken_ReturnsNull() {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));
        String plainJwt = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0LXN1YmplY3QifQ.";
        assertNull(validator.validate(plainJwt, connection));
    }

    @Test
    void testValidate_TokenWithWrongKeyId_ReturnsNull() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience(DEFAULT_AUDIENCE)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID("wrong-key-id").build(), claimsSet);
        signedJWT.sign(support.getSigner());

        assertNull(validator.validate(signedJWT.serialize(), connection));
    }

    @Test
    void testValidate_TokenWithNoKeyId_ReturnsNull() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience(DEFAULT_AUDIENCE)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .build();

        SignedJWT signedJWT = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).build(), claimsSet);
        signedJWT.sign(support.getSigner());

        assertNull(validator.validate(signedJWT.serialize(), connection));
    }

    // ============ Claims Validation Integration Tests ============

    @Test
    void testValidate_ValidClientId_Passes() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, new String[] {CLIENT_ID}, null, null));
        assertNotNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testValidate_InvalidClientId_Fails() throws Exception {
        OfflineTokenValidator validator = new OfflineTokenValidator(
                createOfflineConfig(VALIDATOR_NAME, new String[] {"different-client-id"}, null, null));
        assertNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testValidate_ValidScopes_Passes() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, new String[] {"openid"}, null));
        assertNotNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testValidate_MissingRequiredScope_Fails() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, new String[] {"admin"}, null));
        assertNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testValidate_ValidAudience_Passes() throws Exception {
        OfflineTokenValidator validator = new OfflineTokenValidator(
                createOfflineConfig(VALIDATOR_NAME, null, null, new String[] {DEFAULT_AUDIENCE}));
        assertNotNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testValidate_InvalidAudience_Fails() throws Exception {
        OfflineTokenValidator validator = new OfflineTokenValidator(
                createOfflineConfig(VALIDATOR_NAME, null, null, new String[] {"different-audience"}));
        assertNull(validator.validate(support.createValidToken(), connection));
    }

    // ============ Algorithm Validation Tests ============

    @Test
    void testActivation_NoneAlgorithm_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OfflineTokenValidator(createOfflineConfig(
                        VALIDATOR_NAME, null, null, null, new String[] {"RS256", "none"}, 60, 300)));
    }

    @Test
    void testActivation_NoneAlgorithmUppercase_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OfflineTokenValidator(createOfflineConfig(
                        VALIDATOR_NAME, null, null, null, new String[] {"RS256", "NONE"}, 60, 300)));
    }

    @Test
    void testValidate_DisallowedAlgorithm_ReturnsNull() throws Exception {
        // Only allow ES256, but token is signed with RS256
        OfflineTokenValidator validator = new OfflineTokenValidator(
                createOfflineConfig(VALIDATOR_NAME, null, null, null, new String[] {"ES256"}, 60, 300));
        assertNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testValidate_AllowedAlgorithm_Passes() throws Exception {
        // Explicitly allow RS256
        OfflineTokenValidator validator = new OfflineTokenValidator(
                createOfflineConfig(VALIDATOR_NAME, null, null, null, new String[] {"RS256"}, 60, 300));
        assertNotNull(validator.validate(support.createValidToken(), connection));
    }

    // ============ Not-Before (nbf) Validation Tests ============

    @Test
    void testValidate_TokenNotYetValid_ReturnsNull() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        // Create a token with nbf set to 1 hour in the future
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience(DEFAULT_AUDIENCE)
                .expirationTime(new Date(System.currentTimeMillis() + 7200000)) // 2 hours from now
                .notBeforeTime(new Date(System.currentTimeMillis() + 3600000)) // 1 hour from now
                .issueTime(new Date())
                .claim("client_id", CLIENT_ID)
                .claim("scope", DEFAULT_SCOPE)
                .build();

        assertNull(validator.validate(support.createTokenWithClaims(claimsSet), connection));
    }

    @Test
    void testValidate_TokenWithNbfInPast_Passes() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        // Create a token with nbf set to 1 hour in the past
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience(DEFAULT_AUDIENCE)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .notBeforeTime(new Date(System.currentTimeMillis() - 3600000)) // 1 hour ago
                .issueTime(new Date())
                .claim("client_id", CLIENT_ID)
                .claim("scope", DEFAULT_SCOPE)
                .build();

        assertNotNull(validator.validate(support.createTokenWithClaims(claimsSet), connection));
    }

    // ============ Clock Skew Tests ============

    @Test
    void testValidate_TokenWithinClockSkew_Passes() throws Exception {
        // Use large clock skew (2 hours)
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null, null, 7200, 300));

        // Create a token that expired 1 hour ago (but within 2 hour clock skew)
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(SUBJECT)
                .audience(DEFAULT_AUDIENCE)
                .expirationTime(new Date(System.currentTimeMillis() - 3600000)) // 1 hour ago
                .issueTime(new Date(System.currentTimeMillis() - 7200000))
                .claim("client_id", CLIENT_ID)
                .claim("scope", DEFAULT_SCOPE)
                .build();

        assertNotNull(validator.validate(support.createTokenWithClaims(claimsSet), connection));
    }

    // ============ JWK Cache Tests ============

    @Test
    void testValidate_JwkCacheDisabled_StillWorks() throws Exception {
        // Disable JWK caching (TTL = 0)
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null, null, 60, 0));

        assertNotNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testValidate_JwkCacheEnabled_UsesCache() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        // First call - should fetch JWK Set
        assertNotNull(validator.validate(support.createValidToken(), connection));

        // Second call - should use cached JWK Set
        assertNotNull(validator.validate(support.createValidToken(), connection));
    }

    @Test
    void testClearJWKSetCache() throws Exception {
        OfflineTokenValidator validator =
                new OfflineTokenValidator(createOfflineConfig(VALIDATOR_NAME, null, null, null));

        // Populate the cache
        assertNotNull(validator.validate(support.createValidToken(), connection));

        // Clear the cache
        validator.clearJWKSetCache();

        // Should still work after cache is cleared
        assertNotNull(validator.validate(support.createValidToken(), connection));
    }
}
