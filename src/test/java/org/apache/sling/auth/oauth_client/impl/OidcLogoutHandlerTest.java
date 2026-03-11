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

import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.LoginCookieManager;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.testing.mock.osgi.junit5.OsgiContext;
import org.apache.sling.testing.mock.osgi.junit5.OsgiContextExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.osgi.framework.BundleContext;
import org.osgi.util.converter.Converters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for OidcLogoutHandler methods.
 * Tests ID token retrieval from Oak user profiles and logout URL building for OIDC logout.
 */
@ExtendWith(OsgiContextExtension.class)
class OidcLogoutHandlerTest {

    private static final String MOCK_OIDC_PARAM = "mock-oidc-param";

    private OsgiContext osgiContext = new OsgiContext();
    private BundleContext bundleContext;
    private List<ClientConnection> connections;
    private OidcAuthenticationHandler oidcAuthenticationHandler;
    private OidcAuthenticationHandler.Config config;
    private LoginCookieManager loginCookieManager;
    private List<UserInfoProcessor> userInfoProcessors;
    private CryptoService cryptoService;

    @BeforeEach
    void setUp() {
        bundleContext = osgiContext.bundleContext();
        loginCookieManager = mock(LoginCookieManager.class);
        cryptoService = new StubCryptoService();

        // Setup user info processor
        SlingUserInfoProcessorImpl.Config userInfoConfig = Converters.standardConverter()
                .convert(Map.of(
                        "storeAccessToken", false,
                        "storeRefreshToken", false,
                        "connection", MOCK_OIDC_PARAM,
                        "groupsInIdToken", false,
                        "groupsClaimName", "groups"))
                .to(SlingUserInfoProcessorImpl.Config.class);

        UserInfoProcessor userInfoProcessor = new SlingUserInfoProcessorImpl(mock(CryptoService.class), userInfoConfig);
        userInfoProcessors = new ArrayList<>();
        userInfoProcessors.add(userInfoProcessor);

        connections = new ArrayList<>();
        connections.add(MockOidcConnection.DEFAULT_CONNECTION);
    }

    // ========== Tests for getIdTokenFromOak method ==========

    @Test
    void testGetIdTokenFromOak_ServiceSessionNull() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);

        // Mock repository to return null session
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(null);

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler with mock repository
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns null when service session is null
        assertNull(result, "Should return null when service session is null");
    }

    @Test
    void testGetIdTokenFromOak_UserNotFound() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);

        // Mock repository and session
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser")).thenReturn(null);

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns null when user not found
        assertNull(result, "Should return null when user is not found");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_UserIsGroup() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);
        org.apache.jackrabbit.api.security.user.Authorizable mockAuthorizable =
                mock(org.apache.jackrabbit.api.security.user.Authorizable.class);

        // Mock repository and session
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser")).thenReturn(mockAuthorizable);
        when(mockAuthorizable.isGroup()).thenReturn(true);

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns null when authorizable is a group
        assertNull(result, "Should return null when authorizable is a group");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_IdTokenFoundInProfile() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);
        org.apache.jackrabbit.api.security.user.Authorizable mockAuthorizable =
                mock(org.apache.jackrabbit.api.security.user.Authorizable.class);
        javax.jcr.Value mockValue = mock(javax.jcr.Value.class);

        // Mock repository and session
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser")).thenReturn(mockAuthorizable);
        when(mockAuthorizable.isGroup()).thenReturn(false);
        when(mockAuthorizable.hasProperty("profile/id_token")).thenReturn(true);
        when(mockAuthorizable.getProperty("profile/id_token")).thenReturn(new javax.jcr.Value[] {mockValue});
        // Store encrypted value (Base64 encoded by StubCryptoService)
        String plainToken = "my-id-token";
        String encryptedToken = cryptoService.encrypt(plainToken);
        when(mockValue.getString()).thenReturn(encryptedToken);

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns decrypted token (original plaintext)
        assertEquals(plainToken, result, "Should return decrypted id_token from profile");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_IdTokenFoundDirectly() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);
        org.apache.jackrabbit.api.security.user.Authorizable mockAuthorizable =
                mock(org.apache.jackrabbit.api.security.user.Authorizable.class);
        javax.jcr.Value mockValue = mock(javax.jcr.Value.class);

        // Mock repository and session
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser")).thenReturn(mockAuthorizable);
        when(mockAuthorizable.isGroup()).thenReturn(false);
        when(mockAuthorizable.hasProperty("profile/id_token")).thenReturn(false);
        when(mockAuthorizable.hasProperty("id_token")).thenReturn(true);
        when(mockAuthorizable.getProperty("id_token")).thenReturn(new javax.jcr.Value[] {mockValue});
        // Store encrypted value (Base64 encoded by StubCryptoService)
        String plainToken = "my-direct-id-token";
        String encryptedToken = cryptoService.encrypt(plainToken);
        when(mockValue.getString()).thenReturn(encryptedToken);

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns decrypted token (original plaintext)
        assertEquals(plainToken, result, "Should return decrypted id_token directly from user");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_DecryptionFails() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);
        org.apache.jackrabbit.api.security.user.Authorizable mockAuthorizable =
                mock(org.apache.jackrabbit.api.security.user.Authorizable.class);
        javax.jcr.Value mockValue = mock(javax.jcr.Value.class);
        CryptoService mockCryptoService = mock(CryptoService.class);

        // Mock repository and session
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser")).thenReturn(mockAuthorizable);
        when(mockAuthorizable.isGroup()).thenReturn(false);
        when(mockAuthorizable.hasProperty("profile/id_token")).thenReturn(true);
        when(mockAuthorizable.getProperty("profile/id_token")).thenReturn(new javax.jcr.Value[] {mockValue});
        when(mockValue.getString()).thenReturn("encrypted-token");
        when(mockCryptoService.decrypt("encrypted-token")).thenThrow(new RuntimeException("Decryption failed"));

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                mockCryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns null when decryption fails
        assertNull(result, "Should return null when decryption fails");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_NoIdTokenFound() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);
        org.apache.jackrabbit.api.security.user.Authorizable mockAuthorizable =
                mock(org.apache.jackrabbit.api.security.user.Authorizable.class);

        // Mock repository and session
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser")).thenReturn(mockAuthorizable);
        when(mockAuthorizable.isGroup()).thenReturn(false);
        when(mockAuthorizable.hasProperty("profile/id_token")).thenReturn(false);
        when(mockAuthorizable.hasProperty("id_token")).thenReturn(false);

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns null when no id_token found
        assertNull(result, "Should return null when no id_token found");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_RepositoryException() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);

        // Mock repository to throw exception
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser"))
                .thenThrow(new javax.jcr.RepositoryException("Test repository error"));

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns null when RepositoryException occurs
        assertNull(result, "Should return null when RepositoryException occurs");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_EmptyToken() throws Exception {
        // Setup mocks
        org.apache.sling.jcr.api.SlingRepository mockSlingRepo = mock(org.apache.sling.jcr.api.SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        org.apache.jackrabbit.api.security.user.UserManager mockUserManager =
                mock(org.apache.jackrabbit.api.security.user.UserManager.class);
        org.apache.jackrabbit.api.security.user.Authorizable mockAuthorizable =
                mock(org.apache.jackrabbit.api.security.user.Authorizable.class);
        javax.jcr.Value mockValue = mock(javax.jcr.Value.class);

        // Mock repository and session with empty token
        when(mockSlingRepo.loginService("test-service-user", null)).thenReturn(mockSession);
        when(mockSession.getUserManager()).thenReturn(mockUserManager);
        when(mockUserManager.getAuthorizable("testUser")).thenReturn(mockAuthorizable);
        when(mockAuthorizable.isGroup()).thenReturn(false);
        when(mockAuthorizable.hasProperty("profile/id_token")).thenReturn(true);
        when(mockAuthorizable.getProperty("profile/id_token")).thenReturn(new javax.jcr.Value[] {mockValue});
        when(mockValue.getString()).thenReturn("");

        // Setup configs
        Map<String, Object> configMap = new HashMap<>();
        configMap.put("path", "/test");
        configMap.put("enableSPInitiatedSingleLogout", true);
        configMap.put("logoutRedirectAllowedHosts", new String[] {"localhost"});
        configMap.put("logoutServiceUserName", "test-service-user");
        config = Converters.standardConverter().convert(configMap).to(OidcAuthenticationHandler.Config.class);

        // Create handler
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext,
                connections,
                config,
                loginCookieManager,
                userInfoProcessors,
                cryptoService,
                mockSlingRepo,
                null);

        // Use reflection to call private method
        // Access logoutHandler field via reflection
        java.lang.reflect.Field logoutHandlerField = OidcAuthenticationHandler.class.getDeclaredField("logoutHandler");
        logoutHandlerField.setAccessible(true);
        OidcLogoutHandler logoutHandler = (OidcLogoutHandler) logoutHandlerField.get(oidcAuthenticationHandler);
        String result = logoutHandler.getIdTokenFromOak("testUser");

        // Verify returns null when token is empty
        assertNull(result, "Should return null when id_token is empty");
        verify(mockSession).logout();
    }

    // ========== Tests for buildLogoutUrl method ==========

    @Test
    void testBuildLogoutUrl_WithIdTokenHint() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out";
        String idTokenHint = "test-id-token";

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, idTokenHint);

        // Verify URL contains both id_token_hint and post_logout_redirect_uri
        assertTrue(result.contains("id_token_hint="), "Should contain id_token_hint parameter");
        assertTrue(result.contains("post_logout_redirect_uri="), "Should contain post_logout_redirect_uri parameter");
        assertTrue(result.startsWith("https://idp.example.com/logout?"), "Should start with endpoint URL");
    }

    @Test
    void testBuildLogoutUrl_WithoutIdTokenHint() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out";
        String idTokenHint = null;

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, idTokenHint);

        // Verify URL contains only post_logout_redirect_uri (no id_token_hint)
        assertFalse(result.contains("id_token_hint="), "Should NOT contain id_token_hint parameter");
        assertTrue(result.contains("post_logout_redirect_uri="), "Should contain post_logout_redirect_uri parameter");
        assertTrue(result.startsWith("https://idp.example.com/logout?"), "Should start with endpoint URL");
    }

    @Test
    void testBuildLogoutUrl_WithEmptyIdTokenHint() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out";
        String idTokenHint = "";

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, idTokenHint);

        // Verify URL contains only post_logout_redirect_uri (no id_token_hint)
        assertFalse(result.contains("id_token_hint="), "Should NOT contain id_token_hint parameter");
        assertTrue(result.contains("post_logout_redirect_uri="), "Should contain post_logout_redirect_uri parameter");
    }

    @Test
    void testBuildLogoutUrl_UrlEncoding() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out?param=value with spaces&foo=bar";
        String idTokenHint = "token with spaces";

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, idTokenHint);

        // Verify URLs are properly encoded
        assertTrue(result.contains("id_token_hint=token+with+spaces"), "Should URL-encode id_token_hint");
        assertTrue(
                result.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example.com"),
                "Should URL-encode post_logout_redirect_uri");
    }

    // ========== Tests for resolveConnectionForLogout ==========

    @Test
    void testResolveConnectionForLogout_emptyConnections() {
        OidcLogoutHandler handler = createLogoutHandler(new ArrayList<>(), "some-default", Set.of("localhost"));

        assertNull(handler.resolveConnectionForLogout(), "Should return null when connections is empty");
    }

    @Test
    void testResolveConnectionForLogout_defaultNameNotInMap() {
        // defaultConnectionName set but no matching connection — should return first available
        OidcLogoutHandler handler = createLogoutHandler(connections, "unknown-connection-name", Set.of("localhost"));

        ClientConnection result = handler.resolveConnectionForLogout();
        assertEquals(
                MockOidcConnection.DEFAULT_CONNECTION, result, "Should return first connection when default not found");
    }

    @Test
    void testResolveConnectionForLogout_emptyDefaultName() {
        // Empty defaultConnectionName — should fall through to return first connection
        OidcLogoutHandler handler = createLogoutHandler(connections, "", Set.of("localhost"));

        ClientConnection result = handler.resolveConnectionForLogout();
        assertEquals(
                MockOidcConnection.DEFAULT_CONNECTION,
                result,
                "Should return first connection when default name is empty");
    }

    // ========== Tests for getEndSessionEndpoint ==========

    @Test
    void testGetEndSessionEndpoint_nonOidcConnection() {
        OAuthConnectionImpl oauthConnection = mock(OAuthConnectionImpl.class);
        OidcLogoutHandler handler = createLogoutHandler(connections, MOCK_OIDC_PARAM, Set.of("localhost"));

        assertNull(handler.getEndSessionEndpoint(oauthConnection), "Should return null for non-OidcConnectionImpl");
    }

    @Test
    void testGetEndSessionEndpoint_oidcConnectionWithEndpoint() throws Exception {
        MockOidcConnection oidcConnection = new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "https://idp.example.com",
                new String[0],
                null,
                "https://idp.example.com/logout");
        List<ClientConnection> conns = new ArrayList<>();
        conns.add(oidcConnection);
        OidcLogoutHandler handler = createLogoutHandler(conns, MOCK_OIDC_PARAM, Set.of("localhost"));

        URI result = handler.getEndSessionEndpoint(oidcConnection);
        assertEquals(new URI("https://idp.example.com/logout"), result, "Should return end_session endpoint URI");
    }

    // ========== Tests for UriBuilder.buildRedirectUri ==========

    @Test
    void testUriBuilder_emptySchemeThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> OidcLogoutHandler.UriBuilder.buildRedirectUri("", "localhost", 8080, "/path"),
                "Should throw for empty scheme");
    }

    @Test
    void testUriBuilder_emptyHostThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> OidcLogoutHandler.UriBuilder.buildRedirectUri("http", "", 8080, "/path"),
                "Should throw for empty host");
    }

    @Test
    void testUriBuilder_nullPathDefaultsToRoot() {
        String result = OidcLogoutHandler.UriBuilder.buildRedirectUri("http", "localhost", 8080, null);
        assertTrue(result.endsWith("/"), "Should default null path to root /");
    }

    @Test
    void testUriBuilder_defaultPortOmitted() {
        String http = OidcLogoutHandler.UriBuilder.buildRedirectUri("http", "localhost", 80, "/path");
        assertFalse(http.contains(":80"), "Default HTTP port should be omitted");

        String https = OidcLogoutHandler.UriBuilder.buildRedirectUri("https", "example.com", 443, "/path");
        assertFalse(https.contains(":443"), "Default HTTPS port should be omitted");
    }

    // ========== Tests for getIdTokenFromOak with tokenStore ==========

    @Test
    void testGetIdTokenFromOak_withTokenStore_returnsToken() throws Exception {
        SlingRepository mockRepo = mock(SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        when(mockRepo.loginService("test-service-user", null)).thenReturn(mockSession);

        String plainToken = "stored-id-token";
        OAuthTokenStore mockTokenStore = mock(OAuthTokenStore.class);
        when(mockTokenStore.getIdToken(MockOidcConnection.DEFAULT_CONNECTION, mockSession, "testUser"))
                .thenReturn(plainToken);

        OidcLogoutHandler handler = new OidcLogoutHandler(
                mockRepo,
                cryptoService,
                mockTokenStore,
                Map.of(MOCK_OIDC_PARAM, MockOidcConnection.DEFAULT_CONNECTION),
                MOCK_OIDC_PARAM,
                "test-service-user",
                "/",
                Set.of("localhost"));

        String result = handler.getIdTokenFromOak("testUser");

        assertEquals(plainToken, result, "Should return token from tokenStore");
        verify(mockSession).logout();
    }

    @Test
    void testGetIdTokenFromOak_withTokenStore_noConnectionAvailable() throws Exception {
        SlingRepository mockRepo = mock(SlingRepository.class);
        org.apache.jackrabbit.api.JackrabbitSession mockSession =
                mock(org.apache.jackrabbit.api.JackrabbitSession.class);
        when(mockRepo.loginService("test-service-user", null)).thenReturn(mockSession);

        OAuthTokenStore mockTokenStore = mock(OAuthTokenStore.class);

        OidcLogoutHandler handler = new OidcLogoutHandler(
                mockRepo,
                cryptoService,
                mockTokenStore,
                Map.of(), // no connections
                "",
                "test-service-user",
                "/",
                Set.of("localhost"));

        String result = handler.getIdTokenFromOak("testUser");

        assertNull(result, "Should return null when no connection is available");
        verify(mockSession).logout();
    }

    // ========== Helper ==========

    private OidcLogoutHandler createLogoutHandler(
            List<ClientConnection> connectionList, String defaultName, Set<String> allowedHosts) {
        Map<String, ClientConnection> connectionMap = new HashMap<>();
        for (ClientConnection c : connectionList) {
            connectionMap.put(c.name(), c);
        }
        return new OidcLogoutHandler(
                mock(SlingRepository.class),
                cryptoService,
                null,
                connectionMap,
                defaultName,
                "service-user",
                "/",
                allowedHosts);
    }
}
