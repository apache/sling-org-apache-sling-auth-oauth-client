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
import java.util.List;

import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.sling.commons.crypto.CryptoService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedirectHelperTest {

    final int COOKIE_EXPIRE_SECONDS = 300;

    @Test
    void testFindLongestPathMatchingWithValidPaths() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "http://example.com/a/b/c/d";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a/b/c", result);
    }

    @Test
    void testFindLongestPathMatchingWithNoMatchingPath() {
        String[] paths = {"/x/y", "/z"};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithEmptyPaths() {
        String[] paths = {};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithNullUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String result = RedirectHelper.findLongestPathMatching(paths, null);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithEmptyUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String result = RedirectHelper.findLongestPathMatching(paths, "");
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithSinglePath() {
        String[] paths = {"/a"};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a", result);
    }

    @Test
    void testFindLongestPathMatchingWithInvalidUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "invalid-url";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithSibling() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "http://example.com/a/b/c_sibling/d";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a/b", result);
    }

    @Test
    void testValidateRedirectWithValidRelativeUrl() throws OAuthEntryPointException {
        // Should not throw exception for valid relative URLs
        RedirectHelper.validateRedirect("/valid/path");
        RedirectHelper.validateRedirect("/another/valid/path");
        RedirectHelper.validateRedirect("/");
    }

    @Test
    void testValidateRedirectWithNullUrl() throws OAuthEntryPointException {
        // Should not throw exception for null URL
        RedirectHelper.validateRedirect(null);
    }

    @Test
    void testValidateRedirectWithEmptyUrl() throws OAuthEntryPointException {
        // Should not throw exception for empty URL
        RedirectHelper.validateRedirect("");
    }

    @Test
    void testValidateRedirectWithInvalidAbsoluteUrl() {
        // Should throw exception for absolute URLs (cross-site redirect)
        OAuthEntryPointException exception = assertThrows(
                OAuthEntryPointException.class, () -> RedirectHelper.validateRedirect("http://example.com/path"));

        assertTrue(exception.getMessage().contains("Invalid redirect URL"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "//example.com/path",
                "https://example.com/path",
                "ftp://example.com/path",
                "javascript:alert('xss')"
            })
    void testValidateRedirectWithInvalidUrl(String url) {
        // Should throw exception for absolute URLs (cross-site redirect)
        OAuthEntryPointException exception =
                assertThrows(OAuthEntryPointException.class, () -> RedirectHelper.validateRedirect(url));

        assertTrue(exception.getMessage().contains("Invalid redirect URL"));
        assertTrue(exception.getCause() instanceof IllegalArgumentException);
    }

    @Test
    void testBuildRedirectTargetWithSingleAudience() {
        ResolvedConnection conn = createMockResolvedConnection();
        CryptoService cryptoService = new StubCryptoService();
        OAuthCookieValue oAuthCookieValue =
                new OAuthCookieValue("perRequestKey", "connectionName", "/redirect", new Nonce("nonce"), null);
        String[] audience = new String[] {"https://api.example.com"};

        RedirectTarget result = RedirectHelper.buildRedirectTarget(
                new String[] {"/"},
                URI.create("/callback"),
                conn,
                oAuthCookieValue,
                cryptoService,
                audience,
                COOKIE_EXPIRE_SECONDS);

        assertNotNull(result);
        assertNotNull(result.uri());
        String uriString = result.uri().toString();
        assertTrue(
                uriString.contains("resource=https%3A%2F%2Fapi.example.com"),
                "Expected resource parameter in URI but got: " + uriString);
    }

    @Test
    void testBuildRedirectTargetWithMultipleAudiences() {
        ResolvedConnection conn = createMockResolvedConnection();
        CryptoService cryptoService = new StubCryptoService();
        OAuthCookieValue oAuthCookieValue =
                new OAuthCookieValue("perRequestKey", "connectionName", "/redirect", new Nonce("nonce"), null);
        String[] audience = new String[] {"https://api1.example.com", "https://api2.example.com"};

        RedirectTarget result = RedirectHelper.buildRedirectTarget(
                new String[] {"/"},
                URI.create("/callback"),
                conn,
                oAuthCookieValue,
                cryptoService,
                audience,
                COOKIE_EXPIRE_SECONDS);

        assertNotNull(result);
        assertNotNull(result.uri());
        String uriString = result.uri().toString();
        // Using Nimbus SDK resources() method properly handles multiple resource values
        assertTrue(
                uriString.contains("resource=https%3A%2F%2Fapi1.example.com"),
                "Expected first resource parameter in URI but got: " + uriString);
        assertTrue(
                uriString.contains("resource=https%3A%2F%2Fapi2.example.com"),
                "Expected second resource parameter in URI but got: " + uriString);
    }

    @Test
    void testBuildRedirectTargetWithEmptyAudience() {
        ResolvedConnection conn = createMockResolvedConnection();
        CryptoService cryptoService = new StubCryptoService();
        OAuthCookieValue oAuthCookieValue =
                new OAuthCookieValue("perRequestKey", "connectionName", "/redirect", new Nonce("nonce"), null);
        String[] audience = new String[] {};

        RedirectTarget result = RedirectHelper.buildRedirectTarget(
                new String[] {"/"},
                URI.create("/callback"),
                conn,
                oAuthCookieValue,
                cryptoService,
                audience,
                COOKIE_EXPIRE_SECONDS);

        assertRedirectTargetHasNoResourceParameter(result);
    }

    @Test
    void testBuildRedirectTargetWithNullAudience() {
        ResolvedConnection conn = createMockResolvedConnection();
        CryptoService cryptoService = new StubCryptoService();
        OAuthCookieValue oAuthCookieValue =
                new OAuthCookieValue("perRequestKey", "connectionName", "/redirect", new Nonce("nonce"), null);

        RedirectTarget result = RedirectHelper.buildRedirectTarget(
                new String[] {"/"},
                URI.create("/callback"),
                conn,
                oAuthCookieValue,
                cryptoService,
                null,
                COOKIE_EXPIRE_SECONDS);

        assertRedirectTargetHasNoResourceParameter(result);
    }

    @Test
    void testBuildRedirectTargetWithAudienceContainingEmptyStrings() {
        ResolvedConnection conn = createMockResolvedConnection();
        CryptoService cryptoService = new StubCryptoService();
        OAuthCookieValue oAuthCookieValue =
                new OAuthCookieValue("perRequestKey", "connectionName", "/redirect", new Nonce("nonce"), null);
        // Array with empty strings, whitespace, and one valid value
        String[] audience = new String[] {"", "  ", "https://api.example.com", null};

        RedirectTarget result = RedirectHelper.buildRedirectTarget(
                new String[] {"/"},
                URI.create("/callback"),
                conn,
                oAuthCookieValue,
                cryptoService,
                audience,
                COOKIE_EXPIRE_SECONDS);

        assertNotNull(result);
        assertNotNull(result.uri());
        String uriString = result.uri().toString();
        assertTrue(
                uriString.contains("resource=https%3A%2F%2Fapi.example.com"),
                "Expected valid resource parameter in URI but got: " + uriString);
        // Count occurrences of "resource=" - should be exactly 1
        int count = uriString.split("resource=", -1).length - 1;
        assertEquals(1, count, "Expected exactly one resource parameter but found " + count);
    }

    @Test
    void testBuildRedirectTargetUsesConfiguredCookieMaxAge() {
        ResolvedConnection conn = createMockResolvedConnection();
        CryptoService cryptoService = new StubCryptoService();
        OAuthCookieValue oAuthCookieValue =
                new OAuthCookieValue("perRequestKey", "connectionName", "/redirect", new Nonce("nonce"), null);

        int customMaxAge = 600;
        RedirectTarget result = RedirectHelper.buildRedirectTarget(
                new String[] {"/"}, URI.create("/callback"), conn, oAuthCookieValue, cryptoService, null, customMaxAge);

        assertNotNull(result);
        assertNotNull(result.cookie());
        assertEquals(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY, result.cookie().getName());
        assertEquals(customMaxAge, result.cookie().getMaxAge());
    }

    private ResolvedConnection createMockResolvedConnection() {
        ResolvedConnection conn = mock(ResolvedConnection.class);
        when(conn.authorizationEndpoint()).thenReturn("http://localhost:8080/authorize");
        when(conn.tokenEndpoint()).thenReturn("http://localhost:8080/token");
        when(conn.clientId()).thenReturn("client-id");
        when(conn.clientSecret()).thenReturn("client-secret");
        when(conn.scopes()).thenReturn(List.of("openid"));
        when(conn.additionalAuthorizationParameters()).thenReturn(List.of());
        return conn;
    }

    private void assertRedirectTargetHasNoResourceParameter(RedirectTarget result) {
        assertNotNull(result);
        assertNotNull(result.uri());
        String uriString = result.uri().toString();
        assertFalse(uriString.contains("resource="), "Expected no resource parameter in URI but got: " + uriString);
    }
}
