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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.commons.crypto.CryptoService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.osgi.util.converter.Converters;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class SlingUserInfoProcessorImplTest {

    @Mock
    private CryptoService cryptoService = mock(CryptoService.class);

    private SlingUserInfoProcessorImpl processor;

    private static final String TEST_SUBJECT = "test-subject-123";
    private static final String TEST_IDP = "test-idp";
    private static final String TEST_ACCESS_TOKEN = "test-access-token";
    private static final String TEST_REFRESH_TOKEN = "test-refresh-token";
    private static final String ENCRYPTED_TOKEN = "encrypted-token";
    private static final String ENCRYPTED_REFRESH_TOKEN = "encrypted-refresh-token";

    @BeforeEach
    void setUp() {
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);
        processor = new SlingUserInfoProcessorImpl(cryptoService, cfg);
    }

    @Test
    void testProcessWithMinimalTokenResponse() throws Exception {
        // Create minimal token response
        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);

        OidcAuthCredentials result = processor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);
        assertEquals(TEST_SUBJECT, result.getUserId());
        assertEquals(TEST_IDP, result.getIdp());
        assertEquals("", result.getAttribute(".token"));
        assertTrue(result.getAttributes().containsKey(".token"));
        // Should not have any profile attributes when userInfo is null
        assertFalse(result.getAttributes().keySet().stream().anyMatch(name -> name.startsWith("profile/")));
    }

    @Test
    void testProcessWithUserInfo() throws Exception {
        // Create user info JSON
        JSONObject userInfoJson = new JSONObject();
        userInfoJson.put("sub", TEST_SUBJECT);
        userInfoJson.put("email", "test@example.com");
        userInfoJson.put("given_name", "John");
        userInfoJson.put("family_name", "Doe");
        userInfoJson.put("name", "John Doe");

        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);

        OidcAuthCredentials result =
                processor.process(userInfoJson.toJSONString(), tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);
        assertEquals("test@example.com", result.getAttribute("profile/email"));
        assertEquals("John", result.getAttribute("profile/given_name"));
        assertEquals("Doe", result.getAttribute("profile/family_name"));
        assertEquals("John Doe", result.getAttribute("profile/name"));
        assertEquals(TEST_SUBJECT, result.getAttribute("profile/sub"));
    }

    @Test
    void testProcessWithGroupsInUserInfo() throws Exception {
        // Create user info with groups
        JSONObject userInfoJson = new JSONObject();
        userInfoJson.put("sub", TEST_SUBJECT);
        userInfoJson.put("email", "test@example.com");
        JSONArray groups = new JSONArray();
        groups.add("group1");
        groups.add("group2");
        userInfoJson.put("groups", groups);

        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);

        OidcAuthCredentials result =
                processor.process(userInfoJson.toJSONString(), tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);
        assertGroupsContain(result.getGroups(), "group1", "group2");
        // Groups are also present in profile attributes because they're processed from different JSON instances
        assertEquals("[\"group1\",\"group2\"]", result.getAttribute("profile/groups"));
    }

    @Test
    void testProcessWithGroupsInIdToken() throws Exception {
        // Configure to read groups from ID token
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", true,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);
        processor = new SlingUserInfoProcessorImpl(cryptoService, cfg);

        // Create ID token with groups
        List<String> groups = Arrays.asList("admin", "user");
        String tokenResponse = createTokenResponseWithIdToken(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, groups);

        OidcAuthCredentials result = processor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);
        assertGroupsContain(result.getGroups(), "admin", "user");
    }

    @Test
    void testProcessWithIdpInUserNameGroupsInIdToken() throws Exception {
        // Configure to read groups from ID token
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", true,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "idpNameInPrincipals", true,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);
        processor = new SlingUserInfoProcessorImpl(cryptoService, cfg);

        // Create ID token with groups
        List<String> groups = Arrays.asList("admin", "user");
        String tokenResponse = createTokenResponseWithIdToken(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, groups);

        OidcAuthCredentials result = processor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);
        assertEquals(result.getUserId(), TEST_SUBJECT + ";" + TEST_IDP);
        assertGroupsContain(result.getGroups(), "admin" + ";" + TEST_IDP, "user" + ";" + TEST_IDP);
    }

    @Test
    void testStoreAccessToken() throws Exception {
        when(cryptoService.encrypt(anyString())).thenReturn(ENCRYPTED_TOKEN);

        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", true,
                        "storeRefreshToken", false,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);
        processor = new SlingUserInfoProcessorImpl(cryptoService, cfg);

        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);

        OidcAuthCredentials result = processor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);
        assertEquals(ENCRYPTED_TOKEN, result.getAttribute(OAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN));
        verify(cryptoService).encrypt(TEST_ACCESS_TOKEN);
    }

    @Test
    void testStoreRefreshToken() throws Exception {
        when(cryptoService.encrypt(anyString())).thenReturn(ENCRYPTED_REFRESH_TOKEN);

        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", false,
                        "storeRefreshToken", true,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);
        processor = new SlingUserInfoProcessorImpl(cryptoService, cfg);

        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);

        OidcAuthCredentials result = processor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);

        assertEquals(ENCRYPTED_REFRESH_TOKEN, result.getAttribute(OAuthTokenStore.PROPERTY_NAME_REFRESH_TOKEN));
        verify(cryptoService).encrypt(TEST_REFRESH_TOKEN);
    }

    @Test
    void testProcessWithEmptyGroups() throws Exception {
        // Create user info with empty groups array
        JSONObject userInfoJson = new JSONObject();
        userInfoJson.put("sub", TEST_SUBJECT);
        userInfoJson.put("groups", new JSONArray());

        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);

        OidcAuthCredentials result =
                processor.process(userInfoJson.toJSONString(), tokenResponse, TEST_SUBJECT, TEST_IDP);

        assertNotNull(result);
        assertGroupsEmpty(result.getGroups());
    }

    @Test
    void testProcessWithInvalidTokenResponse() {
        String invalidTokenResponse = "invalid-json";

        assertThrows(RuntimeException.class, () -> {
            processor.process(null, invalidTokenResponse, TEST_SUBJECT, TEST_IDP);
        });
    }

    @Test
    void testProcessWithInvalidUserInfo() throws Exception {
        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);
        String invalidUserInfo = "invalid-json";

        assertThrows(RuntimeException.class, () -> {
            processor.process(invalidUserInfo, tokenResponse, TEST_SUBJECT, TEST_IDP);
        });
    }

    @Test
    void testNullConnection() {
        Map<String, String> configMap = new HashMap<>();
        configMap.put("connection", null);

        SlingUserInfoProcessorImpl.Config cfg =
                Converters.standardConverter().convert(configMap).to(SlingUserInfoProcessorImpl.Config.class);

        try {
            new SlingUserInfoProcessorImpl(cryptoService, cfg);
            fail("Expected IllegalArgumentException for null connection name");
        } catch (IllegalArgumentException e) {
            // success
            assertEquals("Connection name must not be null or empty", e.getMessage());
        }
    }

    private String createTokenResponse(String accessToken, String refreshToken) throws Exception {
        // Create a properly formatted OAuth 2.0 token response
        JSONObject tokenResponse = new JSONObject();
        if (accessToken != null) {
            tokenResponse.put("access_token", accessToken);
            tokenResponse.put("token_type", "Bearer");
            tokenResponse.put("expires_in", 3600); // 1 hour
        }
        if (refreshToken != null) {
            tokenResponse.put("refresh_token", refreshToken);
        }
        tokenResponse.put("scope", "openid profile");
        return tokenResponse.toJSONString();
    }

    private String createTokenResponseWithIdToken(String accessToken, String refreshToken, List<String> groups)
            throws Exception {
        // Create a properly formatted OAuth 2.0 token response with ID token
        JSONObject tokenResponse = new JSONObject();

        if (accessToken != null) {
            tokenResponse.put("access_token", accessToken);
            tokenResponse.put("token_type", "Bearer");
            tokenResponse.put("expires_in", 3600); // 1 hour
        }
        if (refreshToken != null) {
            tokenResponse.put("refresh_token", refreshToken);
        }

        SignedJWT idToken = createIdToken(groups);
        tokenResponse.put("id_token", idToken.serialize());
        tokenResponse.put("scope", "openid profile");

        return tokenResponse.toJSONString();
    }

    private SignedJWT createIdToken(List<String> groups) throws Exception {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder()
                .subject(TEST_SUBJECT)
                .issuer("test-issuer")
                .audience("test-audience")
                .issueTime(new java.util.Date())
                .expirationTime(new java.util.Date(System.currentTimeMillis() + 3600000)); // 1 hour from now

        if (groups != null && !groups.isEmpty()) {
            claimsBuilder.claim("groups", groups);
        }

        JWTClaimsSet claims = claimsBuilder.build();

        SignedJWT jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);

        // Sign with a test secret (must be at least 32 bytes for HS256)
        String secret = "test-secret-key-that-is-long-enough-for-hmac-signing-with-hs256";
        MACSigner signer = new MACSigner(secret.getBytes());
        jwt.sign(signer);

        return jwt;
    }

    private void assertGroupsContain(Iterable<String> groups, String... expectedGroups) {
        List<String> groupList = new ArrayList<>();
        groups.forEach(groupList::add);
        assertEquals(expectedGroups.length, groupList.size());
        for (String expectedGroup : expectedGroups) {
            assertTrue(groupList.contains(expectedGroup), "Expected group: " + expectedGroup);
        }
    }

    private void assertGroupsEmpty(Iterable<String> groups) {
        List<String> groupList = new ArrayList<>();
        groups.forEach(groupList::add);
        assertTrue(groupList.isEmpty(), "Expected no groups");
    }

    // ========== Tests for ID token storage (storeIdToken) ==========

    @Test
    void testProcess_StoreIdToken_Success() throws Exception {
        // Setup crypto service mock
        when(cryptoService.encrypt(anyString())).thenReturn("encrypted-id-token");

        // Setup config with storeIdToken enabled
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "storeIdToken", true,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);

        SlingUserInfoProcessorImpl testProcessor = new SlingUserInfoProcessorImpl(cryptoService, cfg);

        // Create token response with ID token
        String idToken = createIdToken(TEST_SUBJECT);
        String tokenResponse = createTokenResponseWithIdToken(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, idToken);

        // Execute
        OidcAuthCredentials result = testProcessor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        // Verify ID token was encrypted and stored
        assertNotNull(result);
        assertTrue(result.getAttributes().containsKey(OAuthTokenStore.PROPERTY_NAME_ID_TOKEN));
        String storedToken = (String) result.getAttribute(OAuthTokenStore.PROPERTY_NAME_ID_TOKEN);
        assertNotNull(storedToken);
        assertEquals("encrypted-id-token", storedToken);
        verify(cryptoService).encrypt(anyString());
    }

    @Test
    void testProcess_StoreIdToken_NullIdToken() throws Exception {
        // Setup config with storeIdToken enabled
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "storeIdToken", true,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);

        // Create mock crypto that can handle nulls
        CryptoService mockCrypto = mock(CryptoService.class);
        when(mockCrypto.encrypt(anyString())).thenAnswer(inv -> "encrypted-" + inv.getArgument(0));

        SlingUserInfoProcessorImpl testProcessor = new SlingUserInfoProcessorImpl(mockCrypto, cfg);

        // Create token response with null ID token (by using non-OIDC response)
        String tokenResponse = createTokenResponse(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN);

        // Execute - should not throw exception
        OidcAuthCredentials result = testProcessor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        // Verify result is returned but no ID token stored
        assertNotNull(result);
        assertFalse(result.getAttributes().containsKey(OAuthTokenStore.PROPERTY_NAME_ID_TOKEN));
    }

    @Test
    void testProcess_StoreIdToken_EmptyIdToken() {
        // Setup config with storeIdToken enabled
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "storeIdToken", true,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);

        SlingUserInfoProcessorImpl testProcessor = new SlingUserInfoProcessorImpl(cryptoService, cfg);

        // Create token response with empty ID token
        String tokenResponse = createTokenResponseWithIdToken(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, "");

        // Execute - should handle gracefully
        OidcAuthCredentials result = testProcessor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        // Verify result is returned but no ID token stored
        assertNotNull(result);
        assertFalse(result.getAttributes().containsKey(OAuthTokenStore.PROPERTY_NAME_ID_TOKEN));
    }

    @Test
    void testProcess_StoreIdToken_EncryptionException() throws Exception {
        // Setup config with storeIdToken enabled
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "storeIdToken", true,
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);

        // Create mock crypto that throws RuntimeException
        CryptoService mockCrypto = mock(CryptoService.class);
        when(mockCrypto.encrypt(anyString())).thenThrow(new RuntimeException("Encryption failed"));

        SlingUserInfoProcessorImpl testProcessor = new SlingUserInfoProcessorImpl(mockCrypto, cfg);

        // Create token response with ID token
        String idToken = createIdToken(TEST_SUBJECT);
        String tokenResponse = createTokenResponseWithIdToken(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, idToken);

        // Execute - should handle exception gracefully
        OidcAuthCredentials result = testProcessor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        // Verify result is returned but no ID token stored (encryption failed)
        assertNotNull(result);
        assertFalse(result.getAttributes().containsKey(OAuthTokenStore.PROPERTY_NAME_ID_TOKEN));
    }

    @Test
    void testProcess_StoreIdToken_Disabled() throws Exception {
        // Setup config with storeIdToken disabled
        SlingUserInfoProcessorImpl.Config cfg = Converters.standardConverter()
                .convert(Map.of(
                        "groupsInIdToken", false,
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "storeIdToken", false, // disabled
                        "groupsClaimName", "groups",
                        "connection", "test"))
                .to(SlingUserInfoProcessorImpl.Config.class);

        SlingUserInfoProcessorImpl testProcessor = new SlingUserInfoProcessorImpl(cryptoService, cfg);

        // Create token response with ID token
        String idToken = createIdToken(TEST_SUBJECT);
        String tokenResponse = createTokenResponseWithIdToken(TEST_ACCESS_TOKEN, TEST_REFRESH_TOKEN, idToken);

        // Execute
        OidcAuthCredentials result = testProcessor.process(null, tokenResponse, TEST_SUBJECT, TEST_IDP);

        // Verify ID token was NOT stored (disabled)
        assertNotNull(result);
        assertFalse(result.getAttributes().containsKey(OAuthTokenStore.PROPERTY_NAME_ID_TOKEN));
    }

    // Helper methods for ID token tests

    private String createIdToken(String subject) throws Exception {
        // Create a simple signed JWT for testing
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer("https://test-issuer.example.com")
                .audience("test-client-id")
                .expirationTime(new java.util.Date(System.currentTimeMillis() + 3600000))
                .issueTime(new java.util.Date())
                .build();

        // Create signed JWT
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);

        // Sign with a test secret
        byte[] secret = "test-secret-key-for-signing-must-be-long".getBytes();
        signedJWT.sign(new com.nimbusds.jose.crypto.MACSigner(secret));

        return signedJWT.serialize();
    }

    private String createTokenResponseWithIdToken(String accessToken, String refreshToken, String idToken) {
        JSONObject json = new JSONObject();
        json.put("access_token", accessToken);
        json.put("refresh_token", refreshToken);
        json.put("token_type", "Bearer");
        json.put("expires_in", 3600);
        if (idToken != null && !idToken.isEmpty()) {
            json.put("id_token", idToken);
        }
        return json.toJSONString();
    }
}
