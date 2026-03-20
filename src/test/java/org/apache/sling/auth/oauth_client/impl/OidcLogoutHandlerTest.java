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

import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for OidcLogoutHandler methods.
 * Tests ID token retrieval from Oak user profiles and logout URL building for OIDC logout.
 */
class OidcLogoutHandlerTest {

    private static final String MOCK_OIDC_PARAM = "mock-oidc-param";

    private List<ClientConnection> connections;
    private Map<String, ClientConnection> connectionsMap;

    @BeforeEach
    void setUp() {
        connections = new ArrayList<>();
        connections.add(MockOidcConnection.DEFAULT_CONNECTION);
        connectionsMap = new HashMap<>();
        connectionsMap.put(MockOidcConnection.DEFAULT_CONNECTION.name(), MockOidcConnection.DEFAULT_CONNECTION);
    }

    // ========== Tests for getIdTokenFromOak method ==========

    @Test
    void testGetIdTokenFromOak_nullResolver() {
        OidcLogoutHandler handler = new OidcLogoutHandler(mock(OAuthTokenStore.class));
        assertNull(
                handler.getIdTokenFromOak(null, MockOidcConnection.DEFAULT_CONNECTION),
                "Should return null when resolver is null");
    }

    @Test
    void testGetIdTokenFromOak_nullConnection() {
        OidcLogoutHandler handler = new OidcLogoutHandler(mock(OAuthTokenStore.class));
        assertNull(
                handler.getIdTokenFromOak(mock(ResourceResolver.class), null),
                "Should return null when connection is null");
    }

    @Test
    void testGetIdTokenFromOak_nullTokenStore() {
        OidcLogoutHandler handler = new OidcLogoutHandler(null);
        assertNull(
                handler.getIdTokenFromOak(mock(ResourceResolver.class), MockOidcConnection.DEFAULT_CONNECTION),
                "Should return null when tokenStore is null");
    }

    @Test
    void testGetIdTokenFromOak_returnsToken() throws Exception {
        String plainToken = "stored-id-token";
        ResourceResolver mockResolver = mock(ResourceResolver.class);
        OAuthTokenStore mockTokenStore = mock(OAuthTokenStore.class);
        when(mockTokenStore.getIdToken(MockOidcConnection.DEFAULT_CONNECTION, mockResolver))
                .thenReturn(plainToken);

        OidcLogoutHandler handler = new OidcLogoutHandler(mockTokenStore);
        String result = handler.getIdTokenFromOak(mockResolver, MockOidcConnection.DEFAULT_CONNECTION);

        assertEquals(plainToken, result, "Should return token from tokenStore");
    }

    @Test
    void testGetIdTokenFromOak_oauthException_returnsNull() throws Exception {
        ResourceResolver mockResolver = mock(ResourceResolver.class);
        OAuthTokenStore mockTokenStore = mock(OAuthTokenStore.class);
        when(mockTokenStore.getIdToken(MockOidcConnection.DEFAULT_CONNECTION, mockResolver))
                .thenThrow(new OAuthException("revoked"));

        OidcLogoutHandler handler = new OidcLogoutHandler(mockTokenStore);
        String result = handler.getIdTokenFromOak(mockResolver, MockOidcConnection.DEFAULT_CONNECTION);

        assertNull(result, "Should return null on OAuthException");
    }

    // ========== Tests for buildLogoutUrl method ==========

    @Test
    void testBuildLogoutUrl_WithIdTokenHint() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out";
        String idTokenHint = "test-id-token";

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, idTokenHint);

        assertTrue(result.contains("id_token_hint="), "Should contain id_token_hint parameter");
        assertTrue(result.contains("post_logout_redirect_uri="), "Should contain post_logout_redirect_uri parameter");
        assertTrue(result.startsWith("https://idp.example.com/logout?"), "Should start with endpoint URL");
    }

    @Test
    void testBuildLogoutUrl_WithoutIdTokenHint() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out";

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, null);

        assertFalse(result.contains("id_token_hint="), "Should NOT contain id_token_hint parameter");
        assertTrue(result.contains("post_logout_redirect_uri="), "Should contain post_logout_redirect_uri parameter");
        assertTrue(result.startsWith("https://idp.example.com/logout?"), "Should start with endpoint URL");
    }

    @Test
    void testBuildLogoutUrl_WithEmptyIdTokenHint() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out";

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, "");

        assertFalse(result.contains("id_token_hint="), "Should NOT contain id_token_hint parameter");
        assertTrue(result.contains("post_logout_redirect_uri="), "Should contain post_logout_redirect_uri parameter");
    }

    @Test
    void testBuildLogoutUrl_UrlEncoding() throws Exception {
        URI endSessionEndpoint = new URI("https://idp.example.com/logout");
        String postLogoutRedirectUri = "https://app.example.com/logged-out?param=value with spaces&foo=bar";
        String idTokenHint = "token with spaces";

        String result = OidcLogoutHandler.buildLogoutUrl(endSessionEndpoint, postLogoutRedirectUri, idTokenHint);

        assertTrue(result.contains("id_token_hint=token+with+spaces"), "Should URL-encode id_token_hint");
        assertTrue(
                result.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example.com"),
                "Should URL-encode post_logout_redirect_uri");
    }

    // ========== Tests for resolveConnectionForLogout ==========

    @Test
    void testResolveConnectionForLogout_emptyConnections() {
        assertNull(
                OidcLogoutHandler.resolveConnectionForLogout(Map.of(), "some-default"),
                "Should return null when connections is empty");
    }

    @Test
    void testResolveConnectionForLogout_defaultNameNotInMap() {
        // defaultConnectionName set but no matching connection — should return null
        assertNull(
                OidcLogoutHandler.resolveConnectionForLogout(connectionsMap, "unknown-connection-name"),
                "Should return null when defaultConnectionName is set but not found");
    }

    @Test
    void testResolveConnectionForLogout_emptyDefaultName() {
        // Empty defaultConnectionName — should fall through to return first connection
        ClientConnection result = OidcLogoutHandler.resolveConnectionForLogout(connectionsMap, "");
        assertEquals(
                MockOidcConnection.DEFAULT_CONNECTION,
                result,
                "Should return first connection when default name is empty");
    }

    // ========== Tests for getEndSessionEndpoint ==========

    @Test
    void testGetEndSessionEndpoint_nonOidcConnection() {
        OAuthConnectionImpl oauthConnection = mock(OAuthConnectionImpl.class);
        OidcLogoutHandler handler = new OidcLogoutHandler(null);

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
        OidcLogoutHandler handler = new OidcLogoutHandler(null);

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
}
