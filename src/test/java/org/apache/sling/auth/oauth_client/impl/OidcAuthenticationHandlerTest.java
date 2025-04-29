/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

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
import com.sun.net.httpserver.HttpServer;
import net.minidev.json.JSONObject;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.LoginCookieManager;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.BundleContext;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OidcAuthenticationHandlerTest {

    private static final String MOCK_OIDC_PARAM = "mock-oidc-param";
    private static final String ISSUER = "myIssuer";
    private SlingRepository repository;
    private BundleContext bundleContext;
    private List<ClientConnection> connections;
    private OAuthStateManager oauthStateManager;
    private OidcAuthenticationHandler oidcAuthenticationHandler;

    private OidcAuthenticationHandler.Config config;
    private LoginCookieManager loginCookieManager;
    private UserInfoProcessor userInfoProcessor;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private HttpServer tokenEndpointServer;
    HttpServer idpServer;


    @BeforeEach
    void initServlet() throws IOException {
        tokenEndpointServer = createHttpServer();
        idpServer = createHttpServer();

        repository = mock(SlingRepository.class);
        bundleContext = mock(BundleContext.class);
        config = mock(OidcAuthenticationHandler.Config.class);
        when(config.idp()).thenReturn("myIdP");
        loginCookieManager = mock(LoginCookieManager.class);
        userInfoProcessor = mock(UserInfoProcessor.class);
        connections = new ArrayList<>();
        connections.add(MockOidcConnection.DEFAULT_CONNECTION);

        oauthStateManager = new StubOAuthStateManager();

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

        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("No authorization code found in authorization response", exception.getMessage());
    }

    @Test
    void extractCredentialsWithoutState() {
        request = mock(HttpServletRequest.class);
        when(request.getQueryString()).thenReturn("code=authorizationCode");
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080"));
        when(request.getCookies()).thenReturn(null);
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("No state found in authorization response", exception.getMessage());
    }

    @Test
    void extractCredentialsWithoutAnyCookies() {
        //Test without any cookie
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        when(request.getCookies()).thenReturn(null);

        IllegalStateException exception = assertThrows(IllegalStateException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Failed state check: No cookies found", exception.getMessage());
    }

    @Test
    void extractCredentialsWithLoginCookie() {
        //Test without any cookie
        when(loginCookieManager.verifyLoginCookie(request)).thenReturn(AuthenticationInfo.FAIL_AUTH);
        createOidcAuthenticationHandler();

        assertEquals(AuthenticationInfo.FAIL_AUTH, oidcAuthenticationHandler.extractCredentials(request, response));
    }

    @Test
    void extractCredentialsWithoutExpectedCookies() {
        //Test without the expected cookie
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        when(request.getCookies()).thenReturn(null);

        //Test with a cookie that not match
        Cookie cookie = mock(Cookie.class);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals(String.format("Failed state check: No request cookie named %s found", OAuthStateManager.COOKIE_NAME_REQUEST_KEY), exception.getMessage());
    }

    @Test
    void extractCredentialsWithNonMatchingState() {
        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("NOTMATECHpart1%7Cpart2");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Failed state check: request keys from client and server are not the same", exception.getMessage());
    }
    @Test
    void extractCredentialsWithMatchingStateWithInvalidConnection() {
        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7CInvalidConnection");
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Requested unknown connection 'InvalidConnection'", exception.getMessage());
    }

    // The idp return a invalid_request error
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidRequestResponse() {
        tokenEndpointServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\":\"invalid_request\"," +
                    "\"error_description\":\"Invalid request\"}";

            exchange.sendResponseHeaders(400, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:"+tokenEndpointServer.getAddress().getPort() ,
                new String[] { "access_type=offline" }, oidcProviderMetadataRegistry ));

        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Error in token response: invalid_request. Status code: 400. Invalid request", exception.getMessage());

    }

    // The idp return a string that is not a valid json
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithUnparsableResponse() {
        tokenEndpointServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\"";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);

        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:"+tokenEndpointServer.getAddress().getPort() ,
                new String[] { "access_type=offline" }, oidcProviderMetadataRegistry ));

        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Invalid JSON: Unexpected End Of File position 8: null", exception.getMessage());

    }

    // The configured idp is an invalid host
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidHost() throws URISyntaxException {
        tokenEndpointServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\"";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);

        when(oidcProviderMetadataRegistry.getTokenEndpoint(anyString())).thenReturn(new URI("http://jfdljfioewms"));
        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://jfdljfioewms" ,
                new String[] { "access_type=offline" }, oidcProviderMetadataRegistry ));


        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("java.net.UnknownHostException: jfdljfioewms", exception.getMessage());
    }

    // Test with a valid connection but with an invalid URI for the token endpoint
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidURI() throws URISyntaxException {
        tokenEndpointServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\"";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);

        when(oidcProviderMetadataRegistry.getTokenEndpoint(anyString())).thenReturn(new URI("http://jfdljfioewms"));
        connections.add(new MockOidcConnection(
                new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "httjfdljfioewms" ,
                new String[] { "access_type=offline" }, oidcProviderMetadataRegistry ));


        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();

        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("URI is not absolute", exception.getMessage());

    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithInvalidIdToken() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();

        //Test with an id token signed by another key, and expired
        RuntimeException exception = assertThrows(RuntimeException.class, () -> extractCredentials_WithMatchingState_WithValidConnection_WithIdToken("eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ0MnFtQ2I2YTJIcHJxR3FZbmhWQm92cUdKRExZam9VTEgxSTNDVkZCRnhBIn0.eyJleHAiOjE3NDQwMTM4MTYsImlhdCI6MTc0NDAxMzUxNiwiYXV0aF90aW1lIjoxNzQ0MDEzNTExLCJqdGkiOiI5NmE5YWI3NS0yNTIzLTQyMjQtOTU5Zi00ZTQ5MWNiZGUyYWUiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU2OTY3L3JlYWxtcy9zbGluZyIsImF1ZCI6Im9pZGMtdGVzdCIsInN1YiI6Ijk2OGQ4MDhjLTU5MjMtNDFiOS1iOTZjLWNhNzJiMWZlOTMzOSIsInR5cCI6IklEIiwiYXpwIjoib2lkYy10ZXN0Iiwic2Vzc2lvbl9zdGF0ZSI6IjMzMTM4YTMzLTM4MjgtNDk0OS1iMTRhLWQ2Y2IyNjcxNWRlOSIsImF0X2hhc2giOiJ4enlkbVlxdW9xYm9TZjJkaHJhdmNBIiwiYWNyIjoiMSIsInNpZCI6IjMzMTM4YTMzLTM4MjgtNDk0OS1iMTRhLWQ2Y2IyNjcxNWRlOSIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoidGVzdCIsImdpdmVuX25hbWUiOiIiLCJmYW1pbHlfbmFtZSI6IiJ9.GGBOBoi9i0Y2NhT0Ypl_DT9Cy98qHh3XuM0E3Ol8zChsDM53RwMGbkI_Rl3t5k4MCl9_bVXMyCy-0X6OsUW6xfN5WY_ET6G_l39Xdk5BXgZUwpVQc03Z0wD7SCN718QkeWc0bi9ucfyE6GHxLKQL3q6rlG0BzH7nQHha74mQW3naZFWvKJTrRng7Zr_ZQOQDEZTSW8sXq_qabQhkJ-j8yeepVnP4Ws5rkqcs0UixZpRvsmYIv5rep5AHDOKHN6SOra42hxREhZaG7Rga9n-T7Zr5_7pajaLElf6TUkdBOol3x6hFH24RbhtxoPIIeqEOUPkGZkrXhHzR4bIKrVa8pB", rsaJWK, "http://localhost:4567"));
        assertEquals("Signed JWT rejected: Another algorithm expected, or no matching key(s) found", exception.getMessage());

    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithWrongClientId() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();

        //Test with an id token with a wrong client id
        RuntimeException exception = assertThrows(RuntimeException.class, () -> extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(createIdToken(rsaJWK, "wrong-client-id", ISSUER), rsaJWK, "http://localhost:4567"));
        assertEquals("Unexpected JWT audience: [wrong-client-id]", exception.getMessage());
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithWrongIssuer() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();

        //Test with an id token signed but with a wrong issuer
        RuntimeException exception = assertThrows(RuntimeException.class, () -> extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(createIdToken(rsaJWK, "client-id", "wrong-issuer"), rsaJWK, "http://localhost:4567"));
        assertEquals("Unexpected JWT issuer: wrong-issuer", exception.getMessage());
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithUserInfo() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        when(config.userInfoEnabled()).thenReturn(true);
        userInfoProcessor = new UserInfoProcessorImpl();
        //Test with an id token signed by another key, and expired
        AuthenticationInfo authInfo = extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(createIdToken(rsaJWK, "client-id", ISSUER), rsaJWK, "http://localhost:4567");
        assertEquals("1234567890", authInfo.get("user.name"));
        assertEquals("testUser", ((OidcAuthCredentials)authInfo.get("user.jcr.credentials")).getAttribute("profile/name"));
    }

    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithoutUserInfo() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        when(config.userInfoEnabled()).thenReturn(false);
        userInfoProcessor = new UserInfoProcessorImpl();
        //Test with an id token signed by another key, and expired
        AuthenticationInfo authInfo = extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(createIdToken(rsaJWK, "client-id", ISSUER), rsaJWK, "http://localhost:4567");
        assertEquals("1234567890", authInfo.get("user.name"));
    }

    // Test with a valid id token but with an invalid user info response that return error
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithInvalidUserInfo() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        when(config.userInfoEnabled()).thenReturn(true);

        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg;
            try {
                responseMsg = "{\"access_token\":\"myAccessToken\"," +
                        "\"expires_in\":\"360\"," +
                        "\"refresh_token\":\"3600\"," +
                        "\"refresh_expires_in\":\"36000\"," +
                        "\"id_token\":\""+createIdToken(rsaJWK,"client-id",ISSUER)+"\"," +
                        "\"token_type\":\"Bearer\"}";
            } catch (JOSEException e) {
                throw new RuntimeException(e);
            }

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        idpServer.createContext("/userinfo", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{\"error\":\"invalid_request\"," +
                    "\"error_description\":\"Invalid request\"}";

            exchange.sendResponseHeaders(400, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        configureWellKnownOidcMetadata(idpServer, rsaJWK, idpServer.getAddress().getHostName()+":"+idpServer.getAddress().getPort() );

        when(config.callbackUri()).thenReturn("http://redirect");

        when(config.callbackUri()).thenReturn("http://redirect");

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:"+idpServer.getAddress().getPort();
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));
        when(oidcProviderMetadataRegistry.getUserInfoEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/userinfo"));
        connections.add(new MockOidcConnection(new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:"+idpServer.getAddress().getPort(),
                new String[] { "access_type=offline" } ,
                oidcProviderMetadataRegistry)
        );
        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();


        userInfoProcessor = new UserInfoProcessorImpl();
        //Test with an id token signed by another key, and expired
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("Error in userinfo response: invalid_request. Status code: 400. Invalid request", exception.getMessage());
    }

    // Test with a valid id token but with an invalid user info response that a non-json string
    @Test
    void extractCredentials_WithMatchingState_WithValidConnection_WithValidIdToken_WithUnparsableUserInfo() throws JOSEException {
        RSAKey rsaJWK = new RSAKeyGenerator(2048)
                .keyID("123")
                .generate();
        when(config.userInfoEnabled()).thenReturn(true);

        idpServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg;
            try {
                responseMsg = "{\"access_token\":\"myAccessToken\"," +
                        "\"expires_in\":\"360\"," +
                        "\"refresh_token\":\"3600\"," +
                        "\"refresh_expires_in\":\"36000\"," +
                        "\"id_token\":\""+createIdToken(rsaJWK,"client-id",ISSUER)+"\"," +
                        "\"token_type\":\"Bearer\"}";
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

        configureWellKnownOidcMetadata(idpServer, rsaJWK, idpServer.getAddress().getHostName()+":"+idpServer.getAddress().getPort() );

        when(config.callbackUri()).thenReturn("http://redirect");

        when(config.callbackUri()).thenReturn("http://redirect");

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:"+idpServer.getAddress().getPort();
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));
        when(oidcProviderMetadataRegistry.getUserInfoEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/userinfo"));
        connections.add(new MockOidcConnection(new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:"+idpServer.getAddress().getPort(),
                new String[] { "access_type=offline" } ,
                oidcProviderMetadataRegistry)
        );
        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();


        userInfoProcessor = new UserInfoProcessorImpl();
        //Test with an id token signed by another key, and expired
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.extractCredentials(request, response));
        assertEquals("com.nimbusds.oauth2.sdk.ParseException: Couldn't parse UserInfo claims: Invalid JSON: Unexpected token this is an error at position 17.", exception.getMessage());
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
    
    private AuthenticationInfo extractCredentials_WithMatchingState_WithValidConnection_WithIdToken(String idToken, RSAKey rsaJWK, String baseUrl) {
        idpServer.createContext("/token", exchange -> {
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    String responseMsg = "{\"access_token\":\"myAccessToken\"," +
                            "\"expires_in\":\"360\"," +
                            "\"refresh_token\":\"3600\"," +
                            "\"refresh_expires_in\":\"36000\"," +
                            "\"id_token\":\""+idToken+"\"," +
                            "\"token_type\":\"Bearer\"}";

                    exchange.sendResponseHeaders(200, responseMsg.length());
                    exchange.getResponseBody().write(responseMsg.getBytes());
                    exchange.close();
                });
        idpServer.createContext("/userinfo", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String responseMsg = "{" +
                    "\"sub\":\"1234567890\"," +
                    "\"name\":\"testUser\"," +
                    "\"groups\":[\"testGroup\"]" +
                    "}";

            exchange.sendResponseHeaders(200, responseMsg.length());
            exchange.getResponseBody().write(responseMsg.getBytes());
            exchange.close();
        });

        configureWellKnownOidcMetadata(idpServer, rsaJWK, baseUrl);

        when(config.callbackUri()).thenReturn("http://redirect");

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:"+idpServer.getAddress().getPort();
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));
        when(oidcProviderMetadataRegistry.getUserInfoEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/userinfo"));
        connections.add(new MockOidcConnection(new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:"+idpServer.getAddress().getPort(),
                new String[] { "access_type=offline" } ,
                oidcProviderMetadataRegistry)
        );
        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();
        return oidcAuthenticationHandler.extractCredentials(request, response);

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
        oidcAuthenticationHandler =  new OidcAuthenticationHandler(repository,
                bundleContext,
                connections,
                oauthStateManager,
                config,
                loginCookieManager,
                userInfoProcessor
        );
    }

    private HttpServer createHttpServer() throws IOException {
        HttpServer httpServer = HttpServer.create(new InetSocketAddress(0), 0);
        httpServer.start();
        return httpServer;
    }

    @Test
    void requestCredentialsDefaultConnection() throws IOException {

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:8080";
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));

        connections.add(new MockOidcConnection(new String[]{"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:8080",
                new String[]{"access_type=offline"},
                oidcProviderMetadataRegistry)
        );

        when(config.defaultConnectionName()).thenReturn(MOCK_OIDC_PARAM);
        when(config.callbackUri()).thenReturn("http://redirect");

        MockResponse mockResponse = new MockResponse();

        createOidcAuthenticationHandler();
        assertTrue(oidcAuthenticationHandler.requestCredentials(request, mockResponse));
        assertTrue(mockResponse.getCookies().stream().anyMatch(cookie -> {
            if (OAuthStateManager.COOKIE_NAME_REQUEST_KEY.equals(cookie.getName())) {
                String cookieValue = cookie.getValue();
                assertNotNull(cookieValue);
                assertTrue(mockResponse.getSendRedirect().contains("state=" + cookieValue));
                return true;
            }
            return false;
        }));

        // Test the Exception on response
        response = mock(HttpServletResponse.class);
        //mock to trow an exception when response.sendRedirect is called
        doThrow(new IOException("Mocked Exception")).when(response).sendRedirect(anyString());
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.requestCredentials(request, response));
        assertEquals("java.io.IOException: Mocked Exception", exception.getMessage());
    }

    @Test
    void requestCredentialsUnknownConnection() {

        //This is the class used by Sling to configure the Authentication Handler
        OidcProviderMetadataRegistry oidcProviderMetadataRegistry = mock(OidcProviderMetadataRegistry.class);
        String mockIdPUrl = "http://localhost:8080";
        when(oidcProviderMetadataRegistry.getJWKSetURI(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/jwks.json"));
        when(oidcProviderMetadataRegistry.getIssuer(mockIdPUrl)).thenReturn(ISSUER);
        when(oidcProviderMetadataRegistry.getAuthorizationEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl+"/authorize"));
        when(oidcProviderMetadataRegistry.getTokenEndpoint(mockIdPUrl)).thenReturn(URI.create(mockIdPUrl + "/token"));

        connections.add(new MockOidcConnection(new String[] {"openid"},
                MOCK_OIDC_PARAM,
                "client-id",
                "client-secret",
                "http://localhost:8080",
                new String[] { "access_type=offline" } ,
                oidcProviderMetadataRegistry)
        );

        when(config.defaultConnectionName()).thenReturn(MOCK_OIDC_PARAM);
        when(config.callbackUri()).thenReturn("http://redirect");

        when(request.getParameter("c")).thenReturn("unknown-connection");
        MockResponse response1 = new MockResponse();

        createOidcAuthenticationHandler();
        assertFalse(oidcAuthenticationHandler.requestCredentials(request, response1));
        assertEquals(HttpServletResponse.SC_BAD_REQUEST, response1.getErrorCode());
        assertEquals("Client requested unknown connection", response1.getErrorMessage());
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
        assertFalse(oidcAuthenticationHandler.authenticationSucceeded(request, response, new AuthenticationInfo("oidc", "testUser")));
    }

    @Test
    void authenticationSucceededLoginManagerWithLoginCookie() {
        when(loginCookieManager.getLoginCookie(request)).thenReturn(new Cookie("test", "test"));
        createOidcAuthenticationHandler();
        assertFalse(oidcAuthenticationHandler.authenticationSucceeded(request, response, new AuthenticationInfo("oidc", "testUser")));
    }

    @Test
    void authenticationSucceededLoginManagerWithNoLoginCookie() {
        when(loginCookieManager.getLoginCookie(request)).thenReturn(null);
        MockResponse mockResponse = new MockResponse();
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080"));
        when(request.getParameter("c")).thenReturn(MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(null);
        when(config.defaultRedirect()).thenReturn("http://localhost:8080");

        createOidcAuthenticationHandler();
        AuthenticationInfo authInfo = new AuthenticationInfo("oidc", "testUser");
        OidcAuthCredentials credentials = new OidcAuthCredentials("testUser", "oidc");
        credentials.setAttribute(".token", "testToken");
        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        assertTrue(oidcAuthenticationHandler.authenticationSucceeded(request, mockResponse, authInfo ));
        assertEquals("http://localhost:8080", mockResponse.getSendRedirect() );
    }

    @Test
    void authenticationSucceededLoginManagerWithNoLoginCookieWithRedirect() throws IOException {
        when(loginCookieManager.getLoginCookie(request)).thenReturn(null);
        MockResponse mockResponse = new MockResponse();
        MockRequest mockRequest = new MockRequest();
        mockRequest.setAttribute(OidcAuthenticationHandler.REDIRECT_ATTRIBUTE_NAME, "http://localhost:8080/redirect");

        when(config.defaultRedirect()).thenReturn("http://localhost:8080");

        createOidcAuthenticationHandler();
        AuthenticationInfo authInfo = new AuthenticationInfo("oidc", "testUser");
        OidcAuthCredentials credentials = new OidcAuthCredentials("testUser", "oidc");
        credentials.setAttribute(".token", "testToken");
        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        assertTrue(oidcAuthenticationHandler.authenticationSucceeded(mockRequest, mockResponse, authInfo ));
        assertEquals("http://localhost:8080/redirect", mockResponse.getSendRedirect() );

        //Test the IOException on response
        HttpServletResponse mockExceptionResponse = mock(HttpServletResponse.class);
        doThrow(new IOException("Mocked Exception")).when(mockExceptionResponse).sendRedirect(anyString());
        RuntimeException exception = assertThrows(RuntimeException.class, () -> oidcAuthenticationHandler.authenticationSucceeded(mockRequest, mockExceptionResponse, authInfo));
        assertEquals("java.io.IOException: Mocked Exception", exception.getMessage());

    }

    @Test
    void resolveOidcConnectionTest() {
        OidcConnectionImpl oidcClientConnection = mock(OidcConnectionImpl.class);
        when(oidcClientConnection.scopes()).thenReturn(new String[0]);
        when(oidcClientConnection.additionalAuthorizationParameters()).thenReturn(new String[0]);
        assertInstanceOf(ResolvedOidcConnection.class, ResolvedOidcConnection.resolve(oidcClientConnection));

        OAuthConnectionImpl oauthClientConnection= mock(OAuthConnectionImpl.class);
        when(oauthClientConnection.name()).thenReturn("test");
        RuntimeException exception = assertThrows(RuntimeException.class, () -> ResolvedOidcConnection.resolve(oauthClientConnection));
        assertEquals("Unable to resolve ClientConnection (name=test) of type org.apache.sling.auth.oauth_client.impl.OAuthConnectionImpl", exception.getMessage());
    }

}