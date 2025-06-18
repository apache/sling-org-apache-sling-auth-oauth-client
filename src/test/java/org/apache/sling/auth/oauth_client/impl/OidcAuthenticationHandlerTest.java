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

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
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
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.sun.net.httpserver.HttpServer;
import net.minidev.json.JSONObject;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.LoginCookieManager;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.apache.sling.testing.mock.osgi.junit.OsgiContext;
import org.apache.sling.testing.mock.osgi.junit5.OsgiContextExtension;
import org.apache.sling.testing.mock.sling.servlet.MockSlingHttpServletRequest;
import org.apache.sling.testing.mock.sling.servlet.MockSlingHttpServletResponse;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.osgi.framework.BundleContext;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(OsgiContextExtension.class)
class OidcAuthenticationHandlerTest {

    private static final String MOCK_OIDC_PARAM = "mock-oidc-param";
    private static final String ISSUER = "myIssuer";
    private OsgiContext osgiContext = new OsgiContext();
    private BundleContext bundleContext;
    private List<ClientConnection> connections;
    private OidcAuthenticationHandler oidcAuthenticationHandler;

    private OidcAuthenticationHandler.Config config;
    private LoginCookieManager loginCookieManager;
    private UserInfoProcessor userInfoProcessor;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private HttpServer tokenEndpointServer;
    private CryptoService cryptoService = new StubCryptoService();
    HttpServer idpServer;

    @BeforeEach
    void initServlet() throws IOException {
        tokenEndpointServer = createHttpServer();
        idpServer = createHttpServer();

        bundleContext = osgiContext.bundleContext();
        config = mock(OidcAuthenticationHandler.Config.class);
        when(config.idp()).thenReturn("myIdP");
        when(config.path()).thenReturn(new String[] {"/"});
        loginCookieManager = mock(LoginCookieManager.class);

        SlingUserInfoProcessorImpl.Config userInfoConfig = mock(SlingUserInfoProcessorImpl.Config.class);
        when(userInfoConfig.storeAccessToken()).thenReturn(false);
        when(userInfoConfig.storeRefreshToken()).thenReturn(false);
        userInfoProcessor = new SlingUserInfoProcessorImpl(mock(CryptoService.class), userInfoConfig);

        when(config.userInfoEnabled()).thenReturn(true);
        when(config.pkceEnabled()).thenReturn(false);
        connections = new ArrayList<>();
        connections.add(MockOidcConnection.DEFAULT_CONNECTION);

        request = mock(HttpServletRequest.class);

        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080"));

        response = mock(HttpServletResponse.class);

        createOidcAuthenticationHandler();
    }

    @AfterEach
    void shutdownServers() {
        tokenEndpointServer.stop(0);
        idpServer.stop(0);
    }

    @Test
    void extractCredentialsWithoutAnyParameter() {
        // The authentication Handler MUST return null to allow other Authentication Handlers to process the request
        assertNull(oidcAuthenticationHandler.extractCredentials(request, response));
    }

    @Test
    void extractCredentialsWithoutAuthorizationCode() {
        request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("state=part1%7Cpart2");
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080"));

        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("No authorization code found in authorization response", exception.getMessage());
    }

    @Test
    void extractCredentialsWithoutState() {
        request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080"));
        when(request.getCookies()).thenReturn(null);
        assertNull(oidcAuthenticationHandler.extractCredentials(request, response));
    }

    @Test
    void extractCredentialsWithoutAnyCookies() {
        // Test without any cookie
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        when(request.getCookies()).thenReturn(null);

        IllegalStateException exception = assertThrows(
                IllegalStateException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Failed state check: No cookies found", exception.getMessage());
    }

    @Test
    void extractCredentialsWithLoginCookie() {
        // Test without any cookie
        when(loginCookieManager.verifyLoginCookie(request)).thenReturn(AuthenticationInfo.FAIL_AUTH);
        createOidcAuthenticationHandler();

        assertEquals(AuthenticationInfo.FAIL_AUTH, oidcAuthenticationHandler.extractCredentials(request, response));
    }

    @Test
    void extractCredentialsWithoutExpectedCookies() {
        // Test without the expected cookie
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        when(request.getCookies()).thenReturn(null);

        // Test with a cookie that not match
        Cookie cookie = mock(Cookie.class);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});
        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals(
                String.format(
                        "Failed state check: No request cookie named %s found",
                        OAuthCookieValue.COOKIE_NAME_REQUEST_KEY),
                exception.getMessage());
    }

    @Test
    void extractCredentialsWithNonMatchingState() {
        Cookie stateCookie = mock(Cookie.class);
        when(stateCookie.getName()).thenReturn(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY);
        when(stateCookie.getValue()).thenReturn(cryptoService.encrypt("non-matchpart1|mock-oidc-param|redirect|nonce"));

        when(request.getCookies()).thenReturn(new Cookie[] {stateCookie});
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals(
                "Failed state check: request keys from client and server are not the same", exception.getMessage());
    }

    @Test
    void extractCredentialsWithMatchingStateWithInvalidConnection() {
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1&nonce=nonce");
        Cookie stateCookie = mock(Cookie.class);
        when(stateCookie.getName()).thenReturn(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY);
        when(stateCookie.getValue())
                .thenReturn(cryptoService.encrypt(
                        "part1|invalid-connection|redirect|nonce|0123456789012345678901234567890123456789123"));

        when(request.getCookies()).thenReturn(new Cookie[] {stateCookie});
        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Requested unknown connection 'invalid-connection'", exception.getMessage());
    }

    // The idp return a invalid_request error
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidRequestResponse() {
        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\":\"invalid_request\"," + "\"error_description\":\"Invalid request\"}";

            exchange.sendResponseHeaders(400, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:" + idpServer.getAddress().getPort(),
                new String[] {"access_type=offline"},
                getOidcProviderMetadataRegistry()));

        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1");
        Cookie[] cookies = createMockCookies();
        when(request.getCookies()).thenReturn(cookies);

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals(
                "Error in token response: invalid_request. Status code: 400. Invalid request", exception.getMessage());
    }

    // The idp return a string that is not a valid json
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithUnparsableResponse() {
        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\"";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:" + idpServer.getAddress().getPort(),
                new String[] {"access_type=offline"},
                getOidcProviderMetadataRegistry()));

        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1");
        Cookie[] cookies = createMockCookies();
        when(request.getCookies()).thenReturn(cookies);

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Invalid JSON", exception.getMessage());
    }

    // The configured idp is an invalid host
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidHost() throws URISyntaxException {
        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\"";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);

        when(oidcProviderMetadataRegistry.getTokenEndpoint(anyString())).thenReturn(new URI("http://jfdljfioewms"));
        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://jfdljfioewms",
                new String[] {"access_type=offline"},
                getOidcProviderMetadataRegistry("http://jfdljfioewms")));

        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1");
        Cookie[] cookies = createMockCookies();
        when(request.getCookies()).thenReturn(cookies);

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("java.net.UnknownHostException: jfdljfioewms", exception.getMessage());
    }

    // Test with a valid connection but with an invalid URI for the token endpoint
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidURI() throws URISyntaxException {
        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\"";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);

        when(oidcProviderMetadataRegistry.getTokenEndpoint(anyString())).thenReturn(new URI("http://jfdljfioewms"));
        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "httjfdljfioewms",
                new String[] {"access_type=offline"},
                getOidcProviderMetadataRegistry("httjfdljfioewms")));

        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1");
        Cookie[] cookies = createMockCookies();
        when(request.getCookies()).thenReturn(cookies);

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("URI is not absolute", exception.getMessage());
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidIdToken() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();

        RSAKey wrongRsaJWK = new RSAKeyGenerator(2048).keyID("456").generate();

        // Test with an id token signed by another key, and expired
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
                        createIdToken(wrongRsaJWK, "client-id", ISSUER),
                        rsaJWK,
                        "http://localhost:4567",
                        createMockCookies(),
                        false));
        assertEquals(
                "Signed JWT rejected: Another algorithm expected, or no matching key(s) found", exception.getMessage());
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithWrongClientId() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();

        // Test with an id token with a wrong client id
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
                        createIdToken(rsaJWK, "wrong-client-id", ISSUER),
                        rsaJWK,
                        "http://localhost:4567",
                        createMockCookies(),
                        false));
        assertEquals("Unexpected JWT audience: [wrong-client-id]", exception.getMessage());
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithWrongIssuer() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();

        // Test with an id token signed but with a wrong issuer
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
                        createIdToken(rsaJWK, "client-id", "wrong-issuer"),
                        rsaJWK,
                        "http://localhost:4567",
                        createMockCookies(),
                        false));
        assertEquals("Unexpected JWT issuer: wrong-issuer", exception.getMessage());
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithUserInfo() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        when(config.userInfoEnabled()).thenReturn(true);
        // Test with an id token signed by another key, and expired
        AuthenticationInfo authInfo = extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
                createIdToken(rsaJWK, "client-id", ISSUER),
                rsaJWK,
                "http://localhost:4567",
                createMockCookies(),
                false);
        assertEquals("1234567890", authInfo.get("user.name"));
        assertEquals(
                "testUser", ((OidcAuthCredentials) authInfo.get("user.jcr.credentials")).getAttribute("profile/name"));
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithUserInfo_WithInvalidNonce()
            throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        when(config.userInfoEnabled()).thenReturn(true);

        Cookie stateCookie = mock(Cookie.class);
        when(stateCookie.getName()).thenReturn(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY);
        when(stateCookie.getValue()).thenReturn(cryptoService.encrypt("part1|mock-oidc-param|redirect|invalid-nonce"));

        // Test with an id token signed by another key, and expired
        RuntimeException exception = assertThrows(
                RuntimeException.class,
                () -> extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
                        createIdToken(rsaJWK, "client-id", ISSUER),
                        rsaJWK,
                        "http://localhost:4567",
                        new Cookie[] {stateCookie},
                        false));
        assertEquals("Unexpected JWT nonce (nonce) claim: nonce", exception.getMessage());
    }

    @Test
    void
            extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithUserInfo_WithPkceEnabledWithCookie()
                    throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        when(config.userInfoEnabled()).thenReturn(true);
        when(config.pkceEnabled()).thenReturn(true);

        Cookie stateCookie = mock(Cookie.class);
        when(stateCookie.getName()).thenReturn(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY);
        when(stateCookie.getValue())
                .thenReturn(cryptoService.encrypt(
                        "part1|mock-oidc-param|redirect|nonce|12345678901234567890123456789012345678901234"));

        when(request.getCookies()).thenReturn(new Cookie[] {stateCookie});

        AuthenticationInfo authInfo = extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
                createIdToken(rsaJWK, "client-id", ISSUER),
                rsaJWK,
                "http://localhost:4567",
                new Cookie[] {stateCookie},
                true);
        // Remark: presence of state and code verifier parameter are checked inside
        // extractCredentials_WithMatchingState_WithValidConnection_WithIdToken
        assertEquals("1234567890", authInfo.get("user.name"));
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithoutUserInfo()
            throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        when(config.userInfoEnabled()).thenReturn(false);
        // Test with an id token signed by another key, and expired
        AuthenticationInfo authInfo = extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
                createIdToken(rsaJWK, "client-id", ISSUER),
                rsaJWK,
                "http://localhost:4567",
                createMockCookies(),
                false);
        assertEquals("1234567890", authInfo.get("user.name"));
    }

    // Test with a valid id token but with an invalid user info response that return error
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithInvalidUserInfo()
            throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        when(config.userInfoEnabled()).thenReturn(true);

        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg;
            try {
                responseMsg = "{\"access_token\":\"myAccessToken\"," + "\"expires_in\":\"360\","
                        + "\"refresh_token\":\"3600\","
                        + "\"refresh_expires_in\":\"36000\","
                        + "\"id_token\":\""
                        + createIdToken(rsaJWK, "client-id", ISSUER) + "\"," + "\"token_type\":\"Bearer\"}";
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        idpServer.createContext("/userinfo", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\":\"invalid_request\"," + "\"error_description\":\"Invalid request\"}";

            exchange.sendResponseHeaders(400, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        configureWellKnownOidcMetadata(
                idpServer,
                rsaJWK,
                idpServer.getAddress().getHostName() + ":"
                        + idpServer.getAddress().getPort());

        when(config.callbackUri()).thenReturn("http://redirect");

        when(config.callbackUri()).thenReturn("http://redirect");

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = getOidcProviderMetadataRegistry();
        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:" + idpServer.getAddress().getPort(),
                new String[] {"access_type=offline"},
                oidcProviderMetadataRegistry));
        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1");
        Cookie[] cookies = createMockCookies();
        when(request.getCookies()).thenReturn(cookies);

        createOidcAuthenticationHandler();

        // Test with an id token signed by another key, and expired
        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals(
                "Error in userinfo response: invalid_request. Status code: 400. Invalid request",
                exception.getMessage());
    }

    @NotNull
    private OidcProviderMetadataRegistry getOidcProviderMetadataRegistry() {
        String mockIdPUrl = "http://localhost:" + idpServer.getAddress().getPort();
        return getOidcProviderMetadataRegistry(mockIdPUrl);
    }

    @NotNull
    private OidcProviderMetadataRegistry getOidcProviderMetadataRegistry(String mockIdPUrl) {
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl))
                .thenReturn(URI.create(mockIdPUrl + "/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));
        when(oidcProviderMetadataRegistry.getUserInfoEndpoint(mockIdPUrl))
                .thenReturn(URI.create(mockIdPUrl + "/userinfo"));
        return oidcProviderMetadataRegistry;
    }

    // Test with a valid id token but with an invalid user info response that a non-json string
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithUnparsableUserInfo()
            throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048).keyID("123").generate();
        when(config.userInfoEnabled()).thenReturn(true);

        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg;
            try {
                responseMsg = "{\"access_token\":\"myAccessToken\"," + "\"expires_in\":\"360\","
                        + "\"refresh_token\":\"3600\","
                        + "\"refresh_expires_in\":\"36000\","
                        + "\"id_token\":\""
                        + createIdToken(rsaJWK, "client-id", ISSUER) + "\"," + "\"token_type\":\"Bearer\"}";
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        idpServer.createContext("/userinfo", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "this is an error";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        configureWellKnownOidcMetadata(
                idpServer,
                rsaJWK,
                idpServer.getAddress().getHostName() + ":"
                        + idpServer.getAddress().getPort());

        when(config.callbackUri()).thenReturn("http://redirect");

        when(config.callbackUri()).thenReturn("http://redirect");

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = getOidcProviderMetadataRegistry();
        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:" + idpServer.getAddress().getPort(),
                new String[] {"access_type=offline"},
                oidcProviderMetadataRegistry));
        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1");
        Cookie[] cookies = createMockCookies();
        when(request.getCookies()).thenReturn(cookies);

        createOidcAuthenticationHandler();

        // Test with an id token signed by another key, and expired
        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals(
                "com.nimbusds.oauth2.sdk.ParseException: Couldn't parse UserInfo claims: Invalid JSON",
                exception.getMessage());
    }

    // make sure we to not raise an exception trying to fetch the state parameter
    @Test
    void extractCredentials_WithParameters() {
        request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("param1=value1&param2=value2");
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080"));

        assertNull(oidcAuthenticationHandler.extractCredentials(request, response));
    }

    private String createIdToken(RSAKey rsaJWK, String clientId, String issuer) throws JOSEException {
        // Create the JWT claims set
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("1234567890")
                .audience(clientId)
                .expirationTime(new Date(new Date().getTime() + 60 * 1000)) // 1 minute expiration
                .issueTime(new Date())
                .claim("name", "John Doe")
                .claim("email", "john.doe@example.com")
                .claim("nonce", "nonce")
                .build();

        // Create the JWS header and specify the RSA algorithm
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaJWK.getKeyID())
                .build();

        // Create the signed JWT
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        // Create the RSA signer
        JWSSigner signer = new RSASSASigner(rsaJWK);

        // Sign the JWT
        signedJWT.sign(signer);

        // Serialize the JWT to a compact form
        return signedJWT.serialize();
    }

    private AuthenticationInfo extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(
            String idToken, RSAKey rsaJWK, String baseUrl, Cookie[] cookies, boolean withPkce) {
        idpServer.createContext("/token", exchange -> {
            if (withPkce) {
                assertTrue(new String(exchange.getRequestBody().readAllBytes())
                        .contains("code_verifier=12345678901234567890123456789012345678901234"));
            }

            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"access_token\":\"myAccessToken\"," + "\"expires_in\":\"360\","
                    + "\"refresh_token\":\"3600\","
                    + "\"refresh_expires_in\":\"36000\","
                    + "\"id_token\":\""
                    + idToken + "\"," + "\"token_type\":\"Bearer\"}";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });
        idpServer.createContext("/userinfo", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg =
                    "{" + "\"sub\":\"1234567890\"," + "\"name\":\"testUser\"," + "\"groups\":[\"testGroup\"]" + "}";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        configureWellKnownOidcMetadata(idpServer, rsaJWK, baseUrl);

        when(config.callbackUri()).thenReturn("http://redirect");

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = getOidcProviderMetadataRegistry();
        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:" + idpServer.getAddress().getPort(),
                new String[] {"access_type=offline"},
                oidcProviderMetadataRegistry));
        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1");
        when(request.getCookies()).thenReturn(cookies);

        createOidcAuthenticationHandler();
        return oidcAuthenticationHandler.extractCredentials(request, response);
    }

    private Cookie[] createMockCookies() {
        Cookie stateCookie = mock(Cookie.class);
        when(stateCookie.getName()).thenReturn(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY);
        when(stateCookie.getValue())
                .thenReturn(cryptoService.encrypt(
                        "part1|mock-oidc-param|redirect|nonce|0123456789012345678901234567890123456789123"));

        return new Cookie[] {stateCookie};
    }

    private void configureWellKnownOidcMetadata(HttpServer server, RSAKey rsaJWK, String baseUrl) {

        // Public JWK Set
        JWKSet publicJWKSet = new JWKSet(rsaJWK.toPublicJWK());

        server.createContext("/jwks.json", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseStr = publicJWKSet.toString();
            exchange.sendResponseHeaders(200, responseStr.length());
            exchange.getResponseBody().write(responseStr.getBytes());
            exchange.close();
        });

        // Serve .well-known OpenID configuration
        server.createContext("/.well-known/openid-configuration", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");

            Map<String, Object> configMap = new HashMap<>();
            configMap.put("issuer", ISSUER);
            configMap.put("authorization_endpoint", baseUrl + "/authorize");
            configMap.put("token_endpoint", baseUrl + "/token");
            configMap.put("userinfo_endpoint", baseUrl + "/userinfo");
            configMap.put("jwks_uri", baseUrl + "/jwks.json");
            configMap.put("response_types_supported", List.of("code", "token", "id_token", "code id_token"));
            configMap.put("subject_types_supported", List.of("public"));
            configMap.put("id_token_signing_alg_values_supported", List.of("RS256"));
            String responseMsg = new JSONObject(configMap).toString();
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.close();
        });
    }

    private void createOidcAuthenticationHandler() {
        oidcAuthenticationHandler = new OidcAuthenticationHandler(
                bundleContext, connections, config, loginCookieManager, userInfoProcessor, cryptoService);
    }

    private HttpServer createHttpServer() throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(0), 0);
        httpServer.start();
        return httpServer;
    }

    @Test
    void requestCredentialsDefaultConnectionIOException() throws IOException {

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:8080";
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl))
                .thenReturn(URI.create(mockIdPUrl + "/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:8080",
                new String[] {"access_type=offline"},
                oidcProviderMetadataRegistry));

        when(config.defaultConnectionName()).thenReturn(MOCK_OIDC_PARAM);
        when(config.callbackUri()).thenReturn("http://redirect");
        when(config.pkceEnabled()).thenReturn(false);
        when(config.path()).thenReturn(new String[] {"/"});

        createOidcAuthenticationHandler();

        // Test the Exception on response
        response = mock(HttpServletResponse.class);
        when(request.getRequestURI()).thenReturn("http://localhost:8080");
        // mock to trow an exception when response.sendRedirect is called
        doThrow(new IOException("Mocked Exception")).when(response).sendRedirect(anyString());
        RuntimeException exception = assertThrows(
                RuntimeException.class, () -> oidcAuthenticationHandler.requestCredentials(request, response));
        assertEquals("java.io.IOException: Mocked Exception", exception.getMessage());
    }

    @Test
    void requestCredentialsDefaultConnectionWithNonce() {

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:8080";
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl))
                .thenReturn(URI.create(mockIdPUrl + "/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:8080",
                new String[] {"access_type=offline"},
                oidcProviderMetadataRegistry));

        when(config.defaultConnectionName()).thenReturn(MOCK_OIDC_PARAM);
        when(config.callbackUri()).thenReturn("http://redirect");
        when(config.pkceEnabled()).thenReturn(false);

        when(request.getRequestURI()).thenReturn("http://localhost");
        MockSlingHttpServletResponse mockResponse = new MockSlingHttpServletResponse();

        createOidcAuthenticationHandler();
        assertTrue(oidcAuthenticationHandler.requestCredentials(request, mockResponse));
        assertTrue(Arrays.stream(mockResponse.getCookies()).anyMatch(cookie -> {
            if (OAuthCookieValue.COOKIE_NAME_REQUEST_KEY.equals(cookie.getName())) {
                OAuthCookieValue oauthCookieValue = new OAuthCookieValue(cookie.getValue(), cryptoService);

                // Verify that state is present in request and in cookie
                assertEquals(302, mockResponse.getStatus());
                assertTrue(mockResponse.getHeader("location").contains("state=" + oauthCookieValue.perRequestKey()));

                // Verify that nonce is present in request and in cookie
                assertTrue(mockResponse
                        .getHeader("location")
                        .contains("nonce=" + oauthCookieValue.nonce().getValue()));

                // Verify that codeVerifier is not present cookie and request
                assertNull(oauthCookieValue.codeVerifier());
                assertFalse(mockResponse.getHeader("location").contains("code_verifier="));

                // Verify that the redirect URI in the cookie is correct
                assertTrue(oauthCookieValue.redirect().equals("http://localhost"));
                return true;
            }
            return false;
        }));
    }

    @Test
    void requestCredentialsDefaultConnectionWithPkce() {
        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:8080";
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl))
                .thenReturn(URI.create(mockIdPUrl + "/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:8080",
                new String[] {"access_type=offline"},
                oidcProviderMetadataRegistry));

        when(config.defaultConnectionName()).thenReturn(MOCK_OIDC_PARAM);
        when(config.callbackUri()).thenReturn("http://redirect");
        when(config.pkceEnabled()).thenReturn(false);

        MockSlingHttpServletResponse mockResponse = new MockSlingHttpServletResponse();

        when(config.pkceEnabled()).thenReturn(true);
        when(config.path()).thenReturn(new String[] {"/"});

        when(request.getRequestURI()).thenReturn("http://localhost");

        createOidcAuthenticationHandler();
        assertTrue(oidcAuthenticationHandler.requestCredentials(request, mockResponse));
        assertTrue(Arrays.stream(mockResponse.getCookies()).anyMatch(cookie -> {
            if (OAuthCookieValue.COOKIE_NAME_REQUEST_KEY.equals(cookie.getName())) {
                String cookieValue = cryptoService.decrypt(cookie.getValue());
                assertNotNull(cookieValue);
                String[] cookieParts = cookieValue.split("\\|");

                // Verify code verifier in the cookie match with code_challenge in the redirect
                assertTrue(mockResponse.getHeader("location").contains("code_challenge_method=S256"));
                assertEquals(302, mockResponse.getStatus());
                CodeVerifier codeVerifier = new CodeVerifier(cookieParts[OAuthCookieValue.CODE_VERIFIER_INDEX]);

                String codeChallenge = mockResponse.getHeader("location")
                        .split("code_challenge=")[1]
                        .split("&")[0];
                CodeChallenge computedCodeChallenge = CodeChallenge.compute(CodeChallengeMethod.S256, codeVerifier);
                assertEquals(codeChallenge, computedCodeChallenge.getValue());

                // Verify that steate in the cookie matches with state in the redirect
                assertEquals(
                        cookieParts[OAuthCookieValue.STATE_INDEX],
                        mockResponse.getHeader("location").split("state=")[1].split("&")[0]);

                // Verify that nonce in the cookie matches with nonce in the redirect
                assertEquals(
                        cookieParts[OAuthCookieValue.NONCE_INDEX],
                        URLDecoder.decode(mockResponse.getHeader("location")
                                .split("nonce=")[1]
                                .split("&")[0]));

                // Verify the redirect URI in the cookie is correct
                assertTrue(cookieParts[OAuthCookieValue.REDIRECT_INDEX].equals("http://localhost"));

                // Verify that the callbackUri is correct
                assertTrue(mockResponse.getHeader("location").contains("redirect_uri=http%3A%2F%2Fredirect"));
                return true;
            }
            return false;
        }));
    }

    @Test
    void requestCredentialsUnknownConnection() {

        // This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:8080";
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl))
                .thenReturn(URI.create(mockIdPUrl + "/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:8080",
                new String[] {"access_type=offline"},
                oidcProviderMetadataRegistry));

        when(config.defaultConnectionName()).thenReturn(MOCK_OIDC_PARAM);
        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getParameter("c")).thenReturn("unknown-connection");
        MockSlingHttpServletResponse response1 = new MockSlingHttpServletResponse();

        createOidcAuthenticationHandler();
        assertFalse(oidcAuthenticationHandler.requestCredentials(request, response1));
        assertEquals(HttpServletResponse.SC_BAD_REQUEST, response1.getStatus());
        assertEquals("Client requested unknown connection", response1.getStatusMessage());
    }

    @Test
    void dropCredentials() {
        // TODO this test doesn't verify anything
        oidcAuthenticationHandler.dropCredentials(request, response);
    }

    @Test
    void authenticationSucceededLoginManagerNotAvailable() {
        loginCookieManager = null;
        createOidcAuthenticationHandler();
        assertFalse(oidcAuthenticationHandler.authenticationSucceeded(
                request, response, new AuthenticationInfo("oidc", "testUser")));
    }

    @Test
    void authenticationSucceededLoginManagerWithLoginCookie() {
        when(request.getRequestURI()).thenReturn("http://localhost:8080");
        when(loginCookieManager.getLoginCookie(request)).thenReturn(new Cookie("test", "test"));
        createOidcAuthenticationHandler();
        assertFalse(oidcAuthenticationHandler.authenticationSucceeded(
                request, response, new AuthenticationInfo("oidc", "testUser")));
    }

    @Test
    void authenticationSucceededLoginManagerWithNoLoginCookie() {
        when(loginCookieManager.getLoginCookie(request)).thenReturn(null);
        MockSlingHttpServletResponse mockResponse = new MockSlingHttpServletResponse();

        createOidcAuthenticationHandler();
        AuthenticationInfo authInfo = new AuthenticationInfo("oidc", "testUser");
        OidcAuthCredentials credentials = new OidcAuthCredentials("testUser", "oidc");
        credentials.setAttribute(".token", "testToken");
        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);

        MockSlingHttpServletRequest mockRequest = new MockSlingHttpServletRequest(bundleContext);
        mockRequest.setAttribute(OidcAuthenticationHandler.REDIRECT_ATTRIBUTE_NAME, "http://localhost:8080");

        when(config.pkceEnabled()).thenReturn(true);
        createOidcAuthenticationHandler();

        assertTrue(oidcAuthenticationHandler.authenticationSucceeded(mockRequest, mockResponse, authInfo));
        assertEquals("http://localhost:8080", mockResponse.getHeader("location"));
        assertEquals(302, mockResponse.getStatus());

        assertTrue(Arrays.stream(mockResponse.getCookies()).anyMatch(cookie -> {
            if (OAuthCookieValue.COOKIE_NAME_REQUEST_KEY.equals(cookie.getName())) {
                int maxAge = cookie.getMaxAge();
                assertEquals(0, maxAge);
                return true;
            }
            return false;
        }));
    }

    @Test
    void resolveOidcConnectionTest() {
        OidcConnectionImpl oidcClientConnection = mock(OidcConnectionImpl.class);
        when(oidcClientConnection.scopes()).thenReturn(new String[0]);
        when(oidcClientConnection.additionalAuthorizationParameters()).thenReturn(new String[0]);
        when(oidcClientConnection.name()).thenReturn("test");
        when(oidcClientConnection.clientId()).thenReturn("client-id");
        when(oidcClientConnection.clientSecret()).thenReturn("client-secret");
        when(oidcClientConnection.authorizationEndpoint()).thenReturn("http://localhost:8080/authorize");
        when(oidcClientConnection.tokenEndpoint()).thenReturn("http://localhost:8080/token");
        when(oidcClientConnection.issuer()).thenReturn("http://localhost:8080/issuer");
        assertInstanceOf(ResolvedOidcConnection.class, ResolvedOidcConnection.resolve(oidcClientConnection));

        OAuthConnectionImpl oauthClientConnection = mock(OAuthConnectionImpl.class);
        when(oauthClientConnection.name()).thenReturn("test");
        RuntimeException exception =
                assertThrows(RuntimeException.class, () -> ResolvedOidcConnection.resolve(oauthClientConnection));
        assertEquals(
                "Unable to resolve ClientConnection (name=test) of type org.apache.sling.auth.oauth_client.impl.OAuthConnectionImpl",
                exception.getMessage());
    }
}
