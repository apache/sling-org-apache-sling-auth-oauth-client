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
import java.util.Map;

import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OidcLogoutHandlerTest {

    private static final ClientConnection DEFAULT = MockOidcConnection.DEFAULT_CONNECTION;
    private static final URI LOGOUT_ENDPOINT = URI.create("https://idp.example.com/logout");

    // ========== getIdTokenFromTokenStore ==========

    @Test
    void getIdTokenFromTokenStore_returnsNullForMissingParams() {
        OAuthTokenStore store = mock(OAuthTokenStore.class);
        assertNull(new OidcLogoutHandler(store).getIdTokenFromTokenStore(null, DEFAULT));
        assertNull(new OidcLogoutHandler(store).getIdTokenFromTokenStore(mock(ResourceResolver.class), null));
        assertNull(new OidcLogoutHandler(null).getIdTokenFromTokenStore(mock(ResourceResolver.class), DEFAULT));
    }

    @Test
    void getIdTokenFromTokenStore_returnsToken() {
        ResourceResolver resolver = mock(ResourceResolver.class);
        OAuthTokenStore store = mock(OAuthTokenStore.class);
        when(store.getIdToken(DEFAULT, resolver)).thenReturn("stored-id-token");
        assertEquals("stored-id-token", new OidcLogoutHandler(store).getIdTokenFromTokenStore(resolver, DEFAULT));
    }

    @Test
    void getIdTokenFromTokenStore_oauthException_returnsNull() {
        ResourceResolver resolver = mock(ResourceResolver.class);
        OAuthTokenStore store = mock(OAuthTokenStore.class);
        when(store.getIdToken(DEFAULT, resolver)).thenThrow(new OAuthException("revoked"));
        assertNull(new OidcLogoutHandler(store).getIdTokenFromTokenStore(resolver, DEFAULT));
    }

    // ========== buildLogoutUrl ==========

    @Test
    void buildLogoutUrl_withIdTokenHint() {
        String result = OidcLogoutHandler.buildLogoutUrl(LOGOUT_ENDPOINT, "https://app.example.com/out", "token");
        assertTrue(result.startsWith("https://idp.example.com/logout?"));
        assertTrue(result.contains("id_token_hint="));
        assertTrue(result.contains("post_logout_redirect_uri="));
    }

    @Test
    void buildLogoutUrl_nullOrEmptyHint_omitsHint() {
        String withNull = OidcLogoutHandler.buildLogoutUrl(LOGOUT_ENDPOINT, "https://app.example.com/out", null);
        String withEmpty = OidcLogoutHandler.buildLogoutUrl(LOGOUT_ENDPOINT, "https://app.example.com/out", "");
        assertFalse(withNull.contains("id_token_hint="));
        assertFalse(withEmpty.contains("id_token_hint="));
    }

    @Test
    void buildLogoutUrl_urlEncoding() {
        String result = OidcLogoutHandler.buildLogoutUrl(
                LOGOUT_ENDPOINT, "https://app.example.com/out?x=y with spaces", "token with spaces");
        assertTrue(result.contains("id_token_hint=token+with+spaces"));
        assertTrue(result.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example.com"));
    }

    // ========== resolveConnectionForLogout ==========

    @Test
    void resolveConnectionForLogout_emptyConnections() {
        assertNull(OidcLogoutHandler.resolveConnectionForLogout(Map.of(), "default"));
    }

    @Test
    void resolveConnectionForLogout_unknownDefault() {
        assertNull(OidcLogoutHandler.resolveConnectionForLogout(Map.of(DEFAULT.name(), DEFAULT), "unknown"));
    }

    @Test
    void resolveConnectionForLogout_emptyDefault_returnsFirst() {
        assertEquals(DEFAULT, OidcLogoutHandler.resolveConnectionForLogout(Map.of(DEFAULT.name(), DEFAULT), ""));
    }

    // ========== getEndSessionEndpoint ==========

    @Test
    void getEndSessionEndpoint_nonOidcConnection() {
        assertNull(new OidcLogoutHandler(null).getEndSessionEndpoint(mock(OAuthConnectionImpl.class)));
    }

    @Test
    void getEndSessionEndpoint_oidcConnection() throws Exception {
        MockOidcConnection conn = new MockOidcConnection(
                new String[] {"openid"},
                "param",
                "client-id",
                "secret",
                "https://idp.example.com",
                new String[0],
                null,
                "https://idp.example.com/logout");
        assertEquals(
                new URI("https://idp.example.com/logout"), new OidcLogoutHandler(null).getEndSessionEndpoint(conn));
    }

    // ========== UriBuilder ==========

    @Test
    void uriBuilder_invalidInputThrows() {
        assertThrows(
                IllegalArgumentException.class,
                () -> OidcLogoutHandler.UriBuilder.buildRedirectUri("", "host", 80, "/"));
        assertThrows(
                IllegalArgumentException.class,
                () -> OidcLogoutHandler.UriBuilder.buildRedirectUri("http", "", 80, "/"));
    }

    @Test
    void uriBuilder_defaultPortsOmittedAndNullPathDefaultsToRoot() {
        assertFalse(OidcLogoutHandler.UriBuilder.buildRedirectUri("http", "localhost", 80, "/")
                .contains(":80"));
        assertFalse(OidcLogoutHandler.UriBuilder.buildRedirectUri("https", "host", 443, "/")
                .contains(":443"));
        assertTrue(OidcLogoutHandler.UriBuilder.buildRedirectUri("http", "localhost", 8080, null)
                .endsWith("/"));
    }
}
