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
package org.apache.sling.auth.oauth_client.spi;

import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Tests for {@link AbstractTokenValidator}.
 */
class AbstractTokenValidatorTest {

    private static final String VALIDATOR_NAME = "test-validator";
    private static final String SUBJECT = "test-subject";

    /**
     * Test implementation of AbstractTokenValidator for testing purposes.
     */
    private static class TestTokenValidator extends AbstractTokenValidator {
        private final TokenValidationResult mockResult;

        TestTokenValidator(
                String name,
                String[] acceptedClientIds,
                String[] requiredScopes,
                String[] requiredAudiences,
                TokenValidationResult mockResult) {
            super(name, acceptedClientIds, requiredScopes, requiredAudiences);
            this.mockResult = mockResult;
        }

        @Override
        @Nullable
        protected TokenValidationResult doValidate(@NotNull String token, @NotNull ClientConnection connection) {
            return mockResult;
        }
    }

    private ClientConnection mockConnection() {
        return mock(ClientConnection.class);
    }

    private JWTClaimsSet createClaimsSet(String clientId, String scope, String... audiences) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .subject(SUBJECT)
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date());

        if (clientId != null) {
            builder.claim("client_id", clientId);
        }
        if (scope != null) {
            builder.claim("scope", scope);
        }
        if (audiences != null && audiences.length > 0) {
            builder.audience(Arrays.asList(audiences));
        }

        return builder.build();
    }

    // ============ Name Tests ============

    @Test
    void testName() {
        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, null, null, null);

        assertEquals(VALIDATOR_NAME, validator.name());
    }

    // ============ Client ID Validation Tests ============

    @Test
    void testValidateClientId_NoConfiguredClientIds_SkipsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("any-client-id", "openid", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
    }

    @Test
    void testValidateClientId_EmptyConfiguredClientIds_SkipsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("any-client-id", "openid", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, new String[] {}, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
    }

    @Test
    void testValidateClientId_MatchingClientId_Passes() {
        String clientId = "valid-client-id";
        JWTClaimsSet claimsSet = createClaimsSet(clientId, "openid", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(
                VALIDATOR_NAME, new String[] {clientId, "other-client-id"}, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
    }

    @Test
    void testValidateClientId_NonMatchingClientId_Fails() {
        JWTClaimsSet claimsSet = createClaimsSet("wrong-client-id", "openid", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, new String[] {"expected-client-id"}, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidateClientId_NoClientIdInToken_Fails() {
        JWTClaimsSet claimsSet = createClaimsSet(null, "openid", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, new String[] {"expected-client-id"}, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidateClientId_AzpClaimFallback_Passes() {
        // Token with azp claim instead of client_id
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(SUBJECT)
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .claim("azp", "valid-client-id")
                .claim("scope", "openid")
                .audience("audience")
                .build();

        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, new String[] {"valid-client-id"}, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
    }

    // ============ Scope Validation Tests ============

    @Test
    void testValidateScopes_NoConfiguredScopes_SkipsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "random-scope", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
    }

    @Test
    void testValidateScopes_EmptyConfiguredScopes_SkipsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "random-scope", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, new String[] {}, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
    }

    @Test
    void testValidateScopes_AllRequiredScopes_Passes() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "openid profile email", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, null, new String[] {"openid", "profile"}, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
    }

    @Test
    void testValidateScopes_MissingRequiredScope_Fails() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "openid profile", "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(
                VALIDATOR_NAME, null, new String[] {"openid", "profile", "admin"}, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidateScopes_NoScopeInToken_Fails() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", null, "audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, null, new String[] {"openid"}, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidateScopes_ScpClaimFallback_Passes() {
        // Token with scp claim instead of scope
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(SUBJECT)
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .claim("client_id", "client-id")
                .claim("scp", "openid profile")
                .audience("audience")
                .build();

        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, null, new String[] {"openid"}, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
    }

    // ============ Audience Validation Tests ============

    @Test
    void testValidateAudience_NoConfiguredAudiences_SkipsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "openid", "any-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, null, null, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
    }

    @Test
    void testValidateAudience_EmptyConfiguredAudiences_SkipsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "openid", "any-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, null, new String[] {}, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
    }

    @Test
    void testValidateAudience_MatchingAudience_Passes() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "openid", "expected-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(
                VALIDATOR_NAME, null, null, new String[] {"expected-audience", "other-audience"}, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
    }

    @Test
    void testValidateAudience_MultipleTokenAudiences_OneMatches_Passes() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "openid", "aud1", "expected-audience", "aud3");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, null, null, new String[] {"expected-audience"}, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
    }

    @Test
    void testValidateAudience_NonMatchingAudience_Fails() {
        JWTClaimsSet claimsSet = createClaimsSet("client-id", "openid", "wrong-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, null, null, new String[] {"expected-audience"}, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidateAudience_NoAudienceInToken_Fails() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(SUBJECT)
                .issuer("https://issuer.example.com")
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .issueTime(new Date())
                .claim("client_id", "client-id")
                .claim("scope", "openid")
                .build();

        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, null, null, new String[] {"expected-audience"}, mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    // ============ Combined Validation Tests ============

    @Test
    void testValidate_AllValidationsPass() {
        JWTClaimsSet claimsSet = createClaimsSet("valid-client", "openid profile", "valid-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(
                VALIDATOR_NAME,
                new String[] {"valid-client"},
                new String[] {"openid", "profile"},
                new String[] {"valid-audience"},
                mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
        assertEquals(claimsSet, result.getClaimsSet());
    }

    @Test
    void testValidate_ClientIdValidationFails_StopsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("wrong-client", "openid profile", "valid-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(
                VALIDATOR_NAME,
                new String[] {"valid-client"},
                new String[] {"openid"},
                new String[] {"valid-audience"},
                mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidate_ScopeValidationFails_StopsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("valid-client", "openid", "valid-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(
                VALIDATOR_NAME,
                new String[] {"valid-client"},
                new String[] {"openid", "admin"},
                new String[] {"valid-audience"},
                mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidate_AudienceValidationFails_StopsValidation() {
        JWTClaimsSet claimsSet = createClaimsSet("valid-client", "openid profile", "wrong-audience");
        TokenValidator.TokenValidationResult mockResult = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        TestTokenValidator validator = new TestTokenValidator(
                VALIDATOR_NAME,
                new String[] {"valid-client"},
                new String[] {"openid"},
                new String[] {"valid-audience"},
                mockResult);

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    @Test
    void testValidate_DoValidateReturnsNull_ReturnsNull() {
        TestTokenValidator validator =
                new TestTokenValidator(VALIDATOR_NAME, null, null, null, null); // doValidate returns null

        TokenValidator.TokenValidationResult result = validator.validate("token", mockConnection());

        assertNull(result);
    }

    // ============ Getter Tests ============

    @Test
    void testGetAcceptedClientIds() {
        String[] clientIds = new String[] {"client1", "client2"};
        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, clientIds, null, null, null);

        assertArrayEquals(clientIds, validator.getAcceptedClientIds());
    }

    @Test
    void testGetRequiredScopes() {
        String[] scopes = new String[] {"openid", "profile"};
        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, scopes, null, null);

        assertArrayEquals(scopes, validator.getRequiredScopes());
    }

    @Test
    void testGetRequiredAudiences() {
        String[] audiences = new String[] {"aud1", "aud2"};
        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, null, audiences, null);

        assertArrayEquals(audiences, validator.getRequiredAudiences());
    }

    @Test
    void testGetters_NullValues() {
        TestTokenValidator validator = new TestTokenValidator(VALIDATOR_NAME, null, null, null, null);

        assertNull(validator.getAcceptedClientIds());
        assertNull(validator.getRequiredScopes());
        assertNull(validator.getRequiredAudiences());
    }
}
