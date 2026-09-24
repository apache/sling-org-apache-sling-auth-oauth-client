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

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.sun.net.httpserver.HttpServer;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.InMemoryOAuthTokenStore;
import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;

@ExtendWith(SlingContextExtension.class)
class OAuthCallbackServletTest {

    private static final String MOCK_OIDC_PARAM = "mock-oidc-param";

    private final SlingContext context = new SlingContext();

    private HttpServer tokenEndpointServer;

    private InMemoryOAuthTokenStore tokenStore;

    private OAuthCallbackServlet servlet;

    private CryptoService cryptoService;

    @BeforeEach
    void setUp() throws IOException {
        tokenEndpointServer = HttpServer.create(new InetSocketAddress(0), 0);
        tokenEndpointServer.start();

        int bindPort = tokenEndpointServer.getAddress().getPort();

        List<ClientConnection> connections = new ArrayList<>(Arrays.asList(
                MockOidcConnection.DEFAULT_CONNECTION,
                new MockOidcConnection(
                        new String[] {"openid"},
                        MOCK_OIDC_PARAM,
                        "client-id",
                        "client-secret",
                        "http://example.com",
                        new String[] {"access_type=offline"}),
                new MockOidcConnection(
                        new String[] {"openid"},
                        "mock-oidc-local",
                        "client-id",
                        "client-secret",
                        "http://localhost:" + bindPort,
                        new String[0])));

        tokenStore = new InMemoryOAuthTokenStore();
        cryptoService = new StubCryptoService();
        servlet = new OAuthCallbackServlet(connections, tokenStore, cryptoService);
    }

    @AfterEach
    void tearDown() {
        tokenEndpointServer.stop(0);
    }

    @Test
    void missingConnectionParameter() throws ServletException, IOException {

        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void malformedStateParameter() throws ServletException, IOException {

        context.request().setQueryString("?code=foo&state=bar");

        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void missingStateCookie() throws ServletException, IOException {

        String state = URLEncoder.encode(
                format("%s|bar", MockOidcConnection.DEFAULT_CONNECTION.name()), StandardCharsets.UTF_8);

        context.request().setQueryString(format("code=foo&state=%s", state));

        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void invalidStateCookie() {

        String cookieValue = String.format("baz|%s", MockOidcConnection.DEFAULT_CONNECTION.name());

        context.request().setQueryString(format("code=foo&state=bar"));
        context.request()
                .addCookie(new Cookie(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY, cryptoService.encrypt(cookieValue)));

        OAuthCallbackException thrown = assertThrowsExactly(
                OAuthCallbackException.class, () -> servlet.service(context.request(), context.response()));
        assertThat(thrown).hasMessage("State check failed");
    }

    @Test
    void errorCode() {

        String cookieValue = format("bar|%s", MockOidcConnection.DEFAULT_CONNECTION.name());

        context.request().setQueryString(format("error=access_denied&state=%s", "bar"));
        context.request()
                .addCookie(new Cookie(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY, cryptoService.encrypt(cookieValue)));

        OAuthCallbackException thrown = assertThrowsExactly(
                OAuthCallbackException.class, () -> servlet.service(context.request(), context.response()));
        assertThat(thrown).hasMessage("Authentication failed");
    }

    @Test
    void unreachableTokenEndpoint() {

        // the token endpoint has no handler configured, will result in a 404

        String cookieValue = "bar|mock-oidc-local";

        context.request().setQueryString(format("code=foo&state=%s", "bar"));
        context.request()
                .addCookie(new Cookie(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY, cryptoService.encrypt(cookieValue)));

        OAuthCallbackException thrown = assertThrowsExactly(
                OAuthCallbackException.class, () -> servlet.service(context.request(), context.response()));

        assertThat(thrown).hasMessage("Token exchange error").cause().hasMessageContaining("code: 404");
    }

    @Test
    void errorResponseFromTokenEndpoint() {

        tokenEndpointServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String response = "{\"error\":\"invalid_request\"}";
            exchange.sendResponseHeaders(400, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();
        });

        String cookieValue = "bar|mock-oidc-local";

        context.request().setQueryString(format("code=foo&state=%s", "bar"));
        context.request()
                .addCookie(new Cookie(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY, cryptoService.encrypt(cookieValue)));

        OAuthCallbackException thrown = assertThrowsExactly(
                OAuthCallbackException.class, () -> servlet.service(context.request(), context.response()));

        assertThat(thrown).hasMessage("Token exchange error").cause().hasMessageContaining("invalid_request");
    }

    @Test
    void successfulCallback() throws IOException, ServletException {

        successfulExecution("bar|mock-oidc-local");

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_NO_CONTENT);
    }

    private void successfulExecution(String cookieValue) throws IOException, ServletException {

        tokenEndpointServer.createContext("/token", exchange -> {
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            String response = "{\"access_token\":\"Token\", \"token_type\":\"Bearer\"}";
            exchange.sendResponseHeaders(200, response.length());
            exchange.getResponseBody().write(response.getBytes());
            exchange.close();
        });

        String state = "bar";

        context.request().setQueryString(format("code=foo&state=%s", state));
        context.request()
                .addCookie(new Cookie(OAuthCookieValue.COOKIE_NAME_REQUEST_KEY, cryptoService.encrypt(cookieValue)));

        servlet.service(context.request(), context.response());

        assertThat(tokenStore.allTokens())
                .hasSize(1)
                .element(0)
                .isNotNull()
                .extracting(OAuthTokens::accessToken)
                .isEqualTo("Token");
    }

    @Test
    void successfulCallbackWithRedirect() throws IOException, ServletException {
        successfulExecution("bar|mock-oidc-local|/local-redirect");

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_FOUND);

        assertThat(context.response().getHeader("Location"))
                .as("location header")
                .isEqualTo("/local-redirect");
    }

    /**
     * Regression test for the redirect double-decode open-redirect vector.
     *
     * <p>At flow start the entry point reads {@code redirect=/%252Fevil.com}; {@code getParameter}
     * decodes it once to {@code /%2Fevil.com}, which passes validation and is stored in the (encrypted)
     * state cookie. The callback must emit that value verbatim. A second URL-decode here would turn it
     * into the protocol-relative {@code //evil.com}, which a container emitting relative redirects would
     * send to the browser as a cross-origin redirect to {@code evil.com}.
     */
    @Test
    void redirectIsNotDoubleDecoded() throws IOException, ServletException {
        successfulExecution("bar|mock-oidc-local|/%2Fevil.com");

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_FOUND);

        String location = context.response().getHeader("Location");
        assertThat(location)
                .as("Location must not be double-decoded into a protocol-relative URL")
                .isEqualTo("/%2Fevil.com")
                .doesNotStartWith("//");
    }

    /**
     * Regression test for the denylist bypass: a backslash after the leading slash ({@code /\evil.com})
     * is normalised by browsers to {@code //evil.com}. The callback re-validates the stored redirect and
     * must reject it rather than emit it in a {@code Location} header.
     */
    @Test
    void redirectWithBackslashIsRejected() throws IOException, ServletException {
        successfulExecution("bar|mock-oidc-local|/\\evil.com");

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
        assertThat(context.response().getHeader("Location"))
                .as("no redirect must be emitted for a rejected target")
                .isNull();
    }
}
