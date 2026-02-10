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

import org.junit.jupiter.api.Test;
import org.osgi.util.converter.Converters;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OidcConnectionImplTest {

    private static final String TEST_NAME = "test-oidc-connection";
    private static final String TEST_BASE_URL = "https://auth.example.com";
    private static final String TEST_AUTH_ENDPOINT = "https://auth.example.com/oauth2/authorize";
    private static final String TEST_TOKEN_ENDPOINT = "https://auth.example.com/oauth2/token";
    private static final String TEST_USER_INFO_URL = "https://auth.example.com/oauth2/userinfo";
    private static final String TEST_JWK_SET_URL = "https://auth.example.com/oauth2/jwks";
    private static final String TEST_ISSUER = "https://auth.example.com";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static final String TEST_CLIENT_SECRET = "test-client-secret";
    private static final String[] TEST_SCOPES = {"openid", "profile", "email"};
    private static final String[] TEST_ADDITIONAL_PARAMS = {"prompt=consent", "access_type=offline"};

    /**
     * Helper method to create config with explicit endpoints and custom parameters (baseUrl as empty string)
     */
    private OidcConnectionImpl.Config createConfigWithExplicitEndpoints(
            String baseUrl, String clientSecret, String[] scopes, String[] additionalParams) {
        return Converters.standardConverter()
                .convert(Map.ofEntries(
                        Map.entry("name", TEST_NAME),
                        Map.entry("baseUrl", baseUrl),
                        Map.entry("authorizationEndpoint", TEST_AUTH_ENDPOINT),
                        Map.entry("tokenEndpoint", TEST_TOKEN_ENDPOINT),
                        Map.entry("userInfoUrl", TEST_USER_INFO_URL),
                        Map.entry("jwkSetURL", TEST_JWK_SET_URL),
                        Map.entry("issuer", TEST_ISSUER),
                        Map.entry("introspectionEndpoint", ""),
                        Map.entry("clientId", TEST_CLIENT_ID),
                        Map.entry("clientSecret", clientSecret),
                        Map.entry("scopes", scopes),
                        Map.entry("additionalAuthorizationParameters", additionalParams)))
                .to(OidcConnectionImpl.Config.class);
    }

    /**
     * Helper method to create config with baseUrl (explicit endpoints as empty strings)
     */
    private OidcConnectionImpl.Config createConfigWithBaseUrl() {
        return createConfigWithBaseUrl(TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS);
    }

    /**
     * Helper method to create config with baseUrl and custom parameters (explicit endpoints as empty strings)
     */
    private OidcConnectionImpl.Config createConfigWithBaseUrl(
            String clientSecret, String[] scopes, String[] additionalParams) {
        return Converters.standardConverter()
                .convert(Map.ofEntries(
                        Map.entry("name", TEST_NAME),
                        Map.entry("baseUrl", TEST_BASE_URL),
                        Map.entry("authorizationEndpoint", ""),
                        Map.entry("tokenEndpoint", ""),
                        Map.entry("userInfoUrl", ""),
                        Map.entry("jwkSetURL", ""),
                        Map.entry("issuer", ""),
                        Map.entry("introspectionEndpoint", ""),
                        Map.entry("clientId", TEST_CLIENT_ID),
                        Map.entry("clientSecret", clientSecret),
                        Map.entry("scopes", scopes),
                        Map.entry("additionalAuthorizationParameters", additionalParams)))
                .to(OidcConnectionImpl.Config.class);
    }

    /**
     * Helper method to create config with empty baseUrl and explicit endpoints as empty strings
     */
    private OidcConnectionImpl.Config createEmptyConfig() {
        return Converters.standardConverter()
                .convert(Map.ofEntries(
                        Map.entry("name", ""),
                        Map.entry("baseUrl", ""),
                        Map.entry("authorizationEndpoint", ""),
                        Map.entry("tokenEndpoint", ""),
                        Map.entry("userInfoUrl", ""),
                        Map.entry("jwkSetURL", ""),
                        Map.entry("issuer", ""),
                        Map.entry("introspectionEndpoint", ""),
                        Map.entry("clientId", ""),
                        Map.entry("clientSecret", ""),
                        Map.entry("scopes", ""),
                        Map.entry("additionalAuthorizationParameters", "")))
                .to(OidcConnectionImpl.Config.class);
    }

    /**
     * Helper method to create OidcConnectionImpl with explicit endpoints config
     */
    private OidcConnectionImpl createConnectionWithExplicitEndpoints() {
        return new OidcConnectionImpl(
                createConfigWithExplicitEndpoints(null, TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS),
                mock(OidcProviderMetadataRegistry.class));
    }

    /**
     * Helper method to create OidcConnectionImpl with baseUrl config
     */
    private OidcConnectionImpl createConnectionWithBaseUrl() {
        return new OidcConnectionImpl(createConfigWithBaseUrl(), mock(OidcProviderMetadataRegistry.class));
    }

    @Test
    void testConstructorWithExplicitEndpointsThrowsError() {
        // The validation logic prevents using explicit endpoints and baseUrl
        OidcConnectionImpl.Config config = createConfigWithExplicitEndpoints(
                TEST_BASE_URL, TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS);
        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new OidcConnectionImpl(config, mockRegistry);
        });

        assertTrue(exception.getMessage().contains("must be provided, not both"));
    }

    @Test
    void testConstructorWithoutConfigThrowsError() {
        // The validation logic prevents using explicit endpoints
        OidcConnectionImpl.Config config = createEmptyConfig();
        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);

        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new OidcConnectionImpl(config, mockRegistry);
        });

        assertTrue(exception.getMessage().contains("issuer) must be provided"));
    }

    @Test
    void testAuthorizationEndpointWithBaseUrl() {
        OidcConnectionImpl.Config config = createConfigWithBaseUrl();
        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedAuthEndpoint = URI.create("https://auth.example.com/oauth2/authorize");
        when(mockRegistry.getAuthorizationEndpoint(TEST_BASE_URL)).thenReturn(expectedAuthEndpoint);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedAuthEndpoint.toString(), connection.authorizationEndpoint());
    }

    @Test
    void testAuthorizationEndpointWithoutBaseUrl() {
        OidcConnectionImpl.Config config =
                createConfigWithExplicitEndpoints("", TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS);
        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedAuthEndpoint = URI.create("https://auth.example.com/oauth2/authorize");
        when(mockRegistry.getAuthorizationEndpoint(TEST_BASE_URL)).thenReturn(expectedAuthEndpoint);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedAuthEndpoint.toString(), connection.authorizationEndpoint());
    }

    @Test
    void testTokenEndpointWithBaseUrl() {
        OidcConnectionImpl.Config config = createConfigWithBaseUrl();

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedTokenEndpoint = URI.create("https://auth.example.com/oauth2/token");
        when(mockRegistry.getTokenEndpoint(TEST_BASE_URL)).thenReturn(expectedTokenEndpoint);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedTokenEndpoint.toString(), connection.tokenEndpoint());
    }

    @Test
    void testTokenEndpointWithoutBaseUrl() {
        OidcConnectionImpl.Config config =
                createConfigWithExplicitEndpoints("", TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS);

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedTokenEndpoint = URI.create("https://auth.example.com/oauth2/token");
        when(mockRegistry.getTokenEndpoint(TEST_BASE_URL)).thenReturn(expectedTokenEndpoint);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedTokenEndpoint.toString(), connection.tokenEndpoint());
    }

    @Test
    void testUserInfoUrlWithBaseUrl() {
        OidcConnectionImpl.Config config = createConfigWithBaseUrl();

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedUserInfoEndpoint = URI.create("https://auth.example.com/oauth2/userinfo");
        when(mockRegistry.getUserInfoEndpoint(TEST_BASE_URL)).thenReturn(expectedUserInfoEndpoint);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedUserInfoEndpoint.toString(), connection.userInfoUrl());
    }

    @Test
    void testUserInfoUrlWithoutBaseUrl() {
        OidcConnectionImpl.Config config =
                createConfigWithExplicitEndpoints("", TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS);

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedUserInfoEndpoint = URI.create("https://auth.example.com/oauth2/userinfo");
        when(mockRegistry.getUserInfoEndpoint(TEST_BASE_URL)).thenReturn(expectedUserInfoEndpoint);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedUserInfoEndpoint.toString(), connection.userInfoUrl());
    }

    @Test
    void testJwkSetURLWithBaseUrl() {
        OidcConnectionImpl.Config config = createConfigWithBaseUrl();

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedJwkSetURI = URI.create("https://auth.example.com/oauth2/jwks");
        when(mockRegistry.getJWKSetURI(TEST_BASE_URL)).thenReturn(expectedJwkSetURI);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedJwkSetURI, connection.jwkSetURL());
    }

    @Test
    void testJwkSetURLWithoutBaseUrl() {
        OidcConnectionImpl.Config config =
                createConfigWithExplicitEndpoints("", TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS);

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        URI expectedJwkSetURI = URI.create("https://auth.example.com/oauth2/jwks");
        when(mockRegistry.getJWKSetURI(TEST_BASE_URL)).thenReturn(expectedJwkSetURI);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedJwkSetURI, connection.jwkSetURL());
    }

    @Test
    void testIssuerWithBaseUrl() {
        OidcConnectionImpl.Config config = createConfigWithBaseUrl();

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        String expectedIssuer = "https://auth.example.com";
        when(mockRegistry.getIssuer(TEST_BASE_URL)).thenReturn(expectedIssuer);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedIssuer, connection.issuer());
    }

    @Test
    void testIssuerWithoutBaseUrl() {
        OidcConnectionImpl.Config config =
                createConfigWithExplicitEndpoints("", TEST_CLIENT_SECRET, TEST_SCOPES, TEST_ADDITIONAL_PARAMS);

        OidcProviderMetadataRegistry mockRegistry = mock(OidcProviderMetadataRegistry.class);
        String expectedIssuer = "https://auth.example.com";
        when(mockRegistry.getIssuer(TEST_BASE_URL)).thenReturn(expectedIssuer);

        OidcConnectionImpl connection = new OidcConnectionImpl(config, mockRegistry);

        // When baseUrl is present, should fetch from registry
        assertEquals(expectedIssuer, connection.issuer());
    }

    @Test
    void testNameReturnsConfiguredName() {
        OidcConnectionImpl connection = createConnectionWithBaseUrl();
        assertEquals(TEST_NAME, connection.name());
    }

    @Test
    void testClientIdReturnsConfiguredClientId() {
        OidcConnectionImpl connection = createConnectionWithBaseUrl();
        assertEquals(TEST_CLIENT_ID, connection.clientId());
    }

    @Test
    void testClientSecretReturnsConfiguredClientSecret() {
        OidcConnectionImpl connection = createConnectionWithBaseUrl();
        assertEquals(TEST_CLIENT_SECRET, connection.clientSecret());
    }

    @Test
    void testClientSecretCanBeEmpty() {
        OidcConnectionImpl.Config config = createConfigWithBaseUrl("", TEST_SCOPES, TEST_ADDITIONAL_PARAMS);
        OidcConnectionImpl connection = new OidcConnectionImpl(config, mock(OidcProviderMetadataRegistry.class));
        assertEquals("", connection.clientSecret());
    }

    @Test
    void testScopesReturnsConfiguredScopes() {
        OidcConnectionImpl connection = createConnectionWithBaseUrl();
        assertArrayEquals(TEST_SCOPES, connection.scopes());
    }

    @Test
    void testScopesReturnsEmptyArrayWhenNoScopes() {
        String[] emptyScopes = new String[0];
        OidcConnectionImpl.Config config =
                createConfigWithBaseUrl(TEST_CLIENT_SECRET, emptyScopes, TEST_ADDITIONAL_PARAMS);
        OidcConnectionImpl connection = new OidcConnectionImpl(config, mock(OidcProviderMetadataRegistry.class));
        assertArrayEquals(emptyScopes, connection.scopes());
    }

    @Test
    void testAdditionalAuthorizationParametersReturnsConfiguredParams() {
        OidcConnectionImpl connection = createConnectionWithBaseUrl();
        assertArrayEquals(TEST_ADDITIONAL_PARAMS, connection.additionalAuthorizationParameters());
    }

    @Test
    void testAdditionalAuthorizationParametersReturnsEmptyArrayWhenNoParams() {
        String[] emptyParams = new String[0];
        OidcConnectionImpl.Config config = createConfigWithBaseUrl(TEST_CLIENT_SECRET, TEST_SCOPES, emptyParams);
        OidcConnectionImpl connection = new OidcConnectionImpl(config, mock(OidcProviderMetadataRegistry.class));
        assertArrayEquals(emptyParams, connection.additionalAuthorizationParameters());
    }

    @Test
    void testBaseUrlReturnsConfiguredValue() {
        OidcConnectionImpl connection = createConnectionWithBaseUrl();
        assertEquals(TEST_BASE_URL, connection.baseUrl());
    }
}
