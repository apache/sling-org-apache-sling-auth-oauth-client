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

import java.io.OutputStream;
import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpServer;
import org.apache.sling.auth.oauth_client.spi.TokenValidator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.apache.sling.auth.oauth_client.impl.TokenValidatorTestSupport.*;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link OnlineTokenValidator}.
 */
class OnlineTokenValidatorTest {

    private static final String VALIDATOR_NAME = "test-online-validator";

    private HttpServer introspectionServer;
    private OidcConnectionImpl connection;

    @BeforeEach
    void setUp() throws Exception {
        introspectionServer = HttpServer.create(new InetSocketAddress(0), 0);
        introspectionServer.start();
        connection = createConnectionWithIntrospection();
    }

    @AfterEach
    void tearDown() {
        if (introspectionServer != null) {
            introspectionServer.stop(0);
        }
    }

    private OidcConnectionImpl createConnectionWithIntrospection() throws Exception {
        TokenValidatorTestSupport support = new TokenValidatorTestSupport();
        return support.createConnection(
                0, "http://localhost:" + introspectionServer.getAddress().getPort() + "/introspect");
    }

    private OidcConnectionImpl createConnectionWithoutIntrospection() throws Exception {
        TokenValidatorTestSupport support = new TokenValidatorTestSupport();
        return support.createConnection(0, "");
    }

    private void setupIntrospectionEndpoint(String responseJson, int statusCode) {
        introspectionServer.createContext("/introspect", exchange -> {
            byte[] responseBytes = responseJson.getBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(statusCode, responseBytes.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(responseBytes);
            }
        });
    }

    private String buildActiveResponse(String subject, String clientId, String scope, String audience) {
        StringBuilder json = new StringBuilder("{\"active\": true");
        if (subject != null) json.append(",\"sub\": \"").append(subject).append("\"");
        if (clientId != null) json.append(",\"client_id\": \"").append(clientId).append("\"");
        if (scope != null) json.append(",\"scope\": \"").append(scope).append("\"");
        if (audience != null) json.append(",\"aud\": \"").append(audience).append("\"");
        json.append(",\"iss\": \"").append(ISSUER).append("\"");
        json.append(",\"exp\": ").append(System.currentTimeMillis() / 1000 + 3600);
        json.append("}");
        return json.toString();
    }

    // ============ Configuration Tests ============

    @Test
    void testActivation_ValidConfig() {
        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, null, null));
        assertEquals(VALIDATOR_NAME, validator.name());
    }

    @Test
    void testActivation_NullName_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OnlineTokenValidator(createOnlineConfig(null, null, null, null)));
    }

    @Test
    void testActivation_EmptyName_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OnlineTokenValidator(createOnlineConfig("", null, null, null)));
    }

    @Test
    void testActivation_EmptyStringInClientIds_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OnlineTokenValidator(
                        createOnlineConfig(VALIDATOR_NAME, new String[] {"valid-client", ""}, null, null)));
    }

    @Test
    void testActivation_EmptyStringInScopes_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OnlineTokenValidator(
                        createOnlineConfig(VALIDATOR_NAME, null, new String[] {"openid", "  "}, null)));
    }

    @Test
    void testActivation_EmptyStringInAudiences_ThrowsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new OnlineTokenValidator(
                        createOnlineConfig(VALIDATOR_NAME, null, null, new String[] {"audience", ""})));
    }

    // ============ Token Validation Tests ============

    @Test
    void testValidate_ActiveToken_ReturnsResult() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid profile", DEFAULT_AUDIENCE), 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, null, null));
        TokenValidator.TokenValidationResult result = validator.validate("valid-token", connection);

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
        assertNotNull(result.getClaimsSet());
    }

    @Test
    void testValidate_InactiveToken_ReturnsNull() {
        setupIntrospectionEndpoint("{\"active\": false}", 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, null, null));
        assertNull(validator.validate("inactive-token", connection));
    }

    @Test
    void testValidate_NoIntrospectionEndpoint_ReturnsNull() throws Exception {
        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, null, null));
        assertNull(validator.validate("token", createConnectionWithoutIntrospection()));
    }

    @Test
    void testValidate_TokenWithoutSubject_ReturnsNull() {
        setupIntrospectionEndpoint(
                "{\"active\": true,\"iss\": \"" + ISSUER + "\",\"client_id\": \"" + CLIENT_ID + "\"}", 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, null, null));
        assertNull(validator.validate("token-without-sub", connection));
    }

    @Test
    void testValidate_IntrospectionError_ReturnsNull() {
        setupIntrospectionEndpoint("{\"error\": \"invalid_token\"}", 400);

        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, null, null));
        assertNull(validator.validate("invalid-token", connection));
    }

    // ============ Claims Extraction Tests ============

    @Test
    void testValidate_ExtractsAllClaims() {
        String responseJson = "{"
                + "\"active\": true,"
                + "\"sub\": \"" + SUBJECT + "\","
                + "\"iss\": \"" + ISSUER + "\","
                + "\"client_id\": \"" + CLIENT_ID + "\","
                + "\"username\": \"testuser\","
                + "\"scope\": \"openid profile email\","
                + "\"aud\": [\"aud1\", \"aud2\"],"
                + "\"exp\": " + (System.currentTimeMillis() / 1000 + 3600) + ","
                + "\"iat\": " + (System.currentTimeMillis() / 1000)
                + "}";
        setupIntrospectionEndpoint(responseJson, 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, null, null));
        TokenValidator.TokenValidationResult result = validator.validate("token", connection);

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
        assertEquals(ISSUER, result.getClaimsSet().getIssuer());
        assertNotNull(result.getClaimsSet().getExpirationTime());
        assertNotNull(result.getClaimsSet().getIssueTime());
    }

    // ============ Claims Validation Integration Tests ============

    @Test
    void testValidate_ValidClientId_Passes() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid", DEFAULT_AUDIENCE), 200);

        OnlineTokenValidator validator =
                new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, new String[] {CLIENT_ID}, null, null));
        assertNotNull(validator.validate("token", connection));
    }

    @Test
    void testValidate_InvalidClientId_Fails() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid", null), 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(
                createOnlineConfig(VALIDATOR_NAME, new String[] {"different-client-id"}, null, null));
        assertNull(validator.validate("token", connection));
    }

    @Test
    void testValidate_ValidScopes_Passes() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid profile email", null), 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(
                createOnlineConfig(VALIDATOR_NAME, null, new String[] {"openid", "profile"}, null));
        assertNotNull(validator.validate("token", connection));
    }

    @Test
    void testValidate_MissingRequiredScope_Fails() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid", null), 200);

        OnlineTokenValidator validator =
                new OnlineTokenValidator(createOnlineConfig(VALIDATOR_NAME, null, new String[] {"admin"}, null));
        assertNull(validator.validate("token", connection));
    }

    @Test
    void testValidate_ValidAudience_Passes() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid", DEFAULT_AUDIENCE), 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(
                createOnlineConfig(VALIDATOR_NAME, null, null, new String[] {DEFAULT_AUDIENCE}));
        assertNotNull(validator.validate("token", connection));
    }

    @Test
    void testValidate_InvalidAudience_Fails() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid", "wrong-audience"), 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(
                createOnlineConfig(VALIDATOR_NAME, null, null, new String[] {"expected-audience"}));
        assertNull(validator.validate("token", connection));
    }

    @Test
    void testValidate_AllClaimsValidation_Passes() {
        setupIntrospectionEndpoint(buildActiveResponse(SUBJECT, CLIENT_ID, "openid profile", DEFAULT_AUDIENCE), 200);

        OnlineTokenValidator validator = new OnlineTokenValidator(createOnlineConfig(
                VALIDATOR_NAME, new String[] {CLIENT_ID}, new String[] {"openid"}, new String[] {DEFAULT_AUDIENCE}));
        TokenValidator.TokenValidationResult result = validator.validate("token", connection);

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
    }
}
