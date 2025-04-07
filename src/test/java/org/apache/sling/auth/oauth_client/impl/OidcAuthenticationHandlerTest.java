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

import com.sun.net.httpserver.HttpServer;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.LoginCookieManager;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.BundleContext;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OidcAuthenticationHandlerTest {

    private static final String MOCK_OIDC_PARAM = "mock-oidc-param";
    private final SlingContext context = new SlingContext();
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

    @BeforeEach
    void initServlet() {
        repository = mock(SlingRepository.class);
        bundleContext = mock(BundleContext.class);
        config = mock(OidcAuthenticationHandler.Config.class);
        when(config.idp()).thenReturn("myIdP");
        loginCookieManager = mock(LoginCookieManager.class);
        userInfoProcessor = mock(UserInfoProcessor.class);
        connections = new ArrayList<ClientConnection>();
        connections.add(MockOidcConnection.DEFAULT_CONNECTION);

        oauthStateManager = new StubOAuthStateManager();

        request = mock(HttpServletRequest.class);
        when(request.getRequestURL()).thenReturn(new StringBuffer("http://localhost:8080"));

        response = mock(HttpServletResponse.class);

        createOidcAuthenticationHandler();
    }

    @Test
    void extractCredentialsWithoutAuthorizationCode() {
        assertNull(oidcAuthenticationHandler.extractCredentials(request, response));
    }

    @Test
    void extractCredentialsWithoutCookies() {
        //Test without any cookie
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        when(request.getCookies()).thenReturn(null);
        assertEquals(AuthenticationInfo.FAIL_AUTH, oidcAuthenticationHandler.extractCredentials(request, response));

        //Test with a cookie that not match
        Cookie cookie = mock(Cookie.class);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});
        assertEquals(AuthenticationInfo.FAIL_AUTH, oidcAuthenticationHandler.extractCredentials(request, response));
    }

    @Test
    void extractCredentialsWithNonMatchinState() {
        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("NOTMATECHpart1%7Cpart2");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7Cpart2");
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});
        assertEquals(AuthenticationInfo.FAIL_AUTH, oidcAuthenticationHandler.extractCredentials(request, response));
    }
    @Test
    void extractCredentialsWithMatchinStateWithInvalidConnection() {
        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7CInvalidConnection");
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});
        assertEquals(AuthenticationInfo.FAIL_AUTH, oidcAuthenticationHandler.extractCredentials(request, response));
    }

    @Test
    void extractCredentials_WithMatchinState_WithValidConnection_WithInvalidServerResponse() throws IOException {
        int bindPort = createHttpServer();
        connections.add(new MockOidcConnection(new String[] {"openid"}, MOCK_OIDC_PARAM, "client-id", "client-secret", "http://localhost:"+bindPort, new String[] { "access_type=offline" } ));

        when(config.callbackUri()).thenReturn("http://redirect");

        Cookie cookie = mock(Cookie.class);
        when(cookie.getName()).thenReturn(OAuthStateManager.COOKIE_NAME_REQUEST_KEY);
        when(cookie.getValue()).thenReturn("part1");
        when(request.getQueryString()).thenReturn("code=authorizationCode&state=part1%7C"+MOCK_OIDC_PARAM);
        when(request.getCookies()).thenReturn(new Cookie[] {cookie});

        createOidcAuthenticationHandler();

        assertEquals(AuthenticationInfo.FAIL_AUTH, oidcAuthenticationHandler.extractCredentials(request, response));
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

    private static int createHttpServer() throws IOException {
        HttpServer tokenEndpointServer = HttpServer.create(new InetSocketAddress(0), 0);
        tokenEndpointServer.start();


        return tokenEndpointServer.getAddress().getPort();
    }


    @Test
    void requestCredentials() {
    }

    @Test
    void dropCredentials() {
    }

    @Test
    void authenticationSucceeded() {
    }
}