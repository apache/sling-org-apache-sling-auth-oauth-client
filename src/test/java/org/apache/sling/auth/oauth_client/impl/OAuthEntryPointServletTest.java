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
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.apache.sling.testing.mock.sling.servlet.MockSlingHttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(SlingContextExtension.class)
class OAuthEntryPointServletTest {

    private static final String MOCK_OIDC_PARAM = "mock-oidc-param";

    private final SlingContext context = new SlingContext();
    private OAuthEntryPointServlet servlet;

    @BeforeEach
    void initServlet() {
        List<ClientConnection> connections = Arrays.asList(
                MockOidcConnection.DEFAULT_CONNECTION,
                new MockOidcConnection(
                        new String[] {"openid"},
                        MOCK_OIDC_PARAM,
                        "client-id",
                        "client-secret",
                        "http://example.com",
                        new String[] {"access_type=offline"}));
        OAuthEntryPointServlet.Config config = mock(OAuthEntryPointServlet.Config.class);
        when(config.requestKeyCookieMaxAgeSeconds())
                .thenReturn(RedirectHelper.DEFAULT_REQUEST_KEY_COOKIE_MAX_AGE_SECONDS);
        servlet = new OAuthEntryPointServlet(connections, new StubCryptoService(), config);
    }

    @Test
    void testRedirectWithValidConnection() throws ServletException, IOException {

        context.request().setQueryString("c=" + MockOidcConnection.DEFAULT_CONNECTION.name());
        MockSlingHttpServletResponse response = context.response();

        servlet.service(context.request(), response);

        URI location = URI.create(Objects.requireNonNull(response.getHeader("Location"), "location header"));

        assertThat(location)
                .as("authentication request uri")
                .hasScheme("https")
                .hasHost("example.com")
                .hasPath("/authorize")
                .hasParameter("scope", "openid")
                .hasParameter("response_type", "code")
                .hasParameter("client_id", "client-id")
                .hasParameter("redirect_uri", "http://localhost/system/sling/oauth/callback")
                .hasParameter("state");
    }

    @Test
    void redirectWithValidConnectionAndCustomParameter() throws ServletException, IOException {

        context.request().setQueryString("c=" + MOCK_OIDC_PARAM);
        MockSlingHttpServletResponse response = context.response();

        servlet.service(context.request(), response);

        URI location = URI.create(Objects.requireNonNull(response.getHeader("Location"), "location header"));

        assertThat(location).as("authentication request uri").hasParameter("access_type", "offline");
    }

    @Test
    void redirectWithValidConnectionAndInvalidRedirect() {

        context.request().setQueryString("c=" + MOCK_OIDC_PARAM + "&redirect=http://invalid-url");
        MockSlingHttpServletResponse response = context.response();

        OAuthEntryPointException exception =
                assertThrows(OAuthEntryPointException.class, () -> servlet.service(context.request(), response));

        assertThat(exception.getMessage()).as("Expected exception message").contains("Internal error");
    }

    @Test
    void redirectWithValidConnectionAndValidRelativeRedirect() throws ServletException, IOException {

        context.request().setQueryString("c=" + MOCK_OIDC_PARAM + "&redirect=/valid/path");
        MockSlingHttpServletResponse response = context.response();

        servlet.service(context.request(), response);

        URI location = URI.create(Objects.requireNonNull(response.getHeader("Location"), "location header"));
        assertThat(location).as("authentication request uri").hasScheme("http");
        assertThat(response.getStatus()).as("response status").isEqualTo(HttpServletResponse.SC_FOUND);
    }

    @Test
    void redirectWithValidConnectionAndHttpsRedirect() {

        context.request().setQueryString("c=" + MOCK_OIDC_PARAM + "&redirect=https://malicious.com");
        MockSlingHttpServletResponse response = context.response();

        OAuthEntryPointException exception =
                assertThrows(OAuthEntryPointException.class, () -> servlet.service(context.request(), response));

        assertThat(exception.getMessage()).as("Expected exception message").contains("Internal error");
        assertThat(exception.getCause()).as("Expected cause").isInstanceOf(OAuthEntryPointException.class);
    }

    @Test
    void redirectWithValidConnectionAndJavaScriptRedirect() {

        context.request().setQueryString("c=" + MOCK_OIDC_PARAM + "&redirect=javascript:alert('xss')");
        MockSlingHttpServletResponse response = context.response();

        OAuthEntryPointException exception =
                assertThrows(OAuthEntryPointException.class, () -> servlet.service(context.request(), response));

        assertThat(exception.getMessage()).as("Expected exception message").contains("Internal error");
        assertThat(exception.getCause()).as("Expected cause").isInstanceOf(OAuthEntryPointException.class);
    }

    @Test
    void redirectWithValidConnectionAndNullRedirect() throws ServletException, IOException {

        context.request().setQueryString("c=" + MOCK_OIDC_PARAM);
        MockSlingHttpServletResponse response = context.response();

        servlet.service(context.request(), response);

        URI location = URI.create(Objects.requireNonNull(response.getHeader("Location"), "location header"));
        assertThat(location).as("authentication request uri").hasScheme("http");
        assertThat(response.getStatus()).as("response status").isEqualTo(HttpServletResponse.SC_FOUND);
    }

    @Test
    void redirectWithValidConnectionAndEmptyRedirect() throws ServletException, IOException {

        context.request().setQueryString("c=" + MOCK_OIDC_PARAM + "&redirect=");
        MockSlingHttpServletResponse response = context.response();

        servlet.service(context.request(), response);

        URI location = URI.create(Objects.requireNonNull(response.getHeader("Location"), "location header"));
        assertThat(location).as("authentication request uri").hasScheme("http");
        assertThat(response.getStatus()).as("response status").isEqualTo(HttpServletResponse.SC_FOUND);
    }

    @Test
    void missingConnectionParameter() throws ServletException, IOException {

        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void invalidConnectionParameter() throws ServletException, IOException {

        context.request().setQueryString("c=invalid");

        MockSlingHttpServletResponse response = context.response();
        servlet.service(context.request(), response);

        assertThat(context.response().getStatus()).as("response code").isEqualTo(HttpServletResponse.SC_BAD_REQUEST);
    }

    @Test
    void usesConfiguredCookieMaxAge() throws ServletException, IOException {
        int customMaxAge = 600;
        OAuthEntryPointServlet.Config config = mock(OAuthEntryPointServlet.Config.class);
        when(config.requestKeyCookieMaxAgeSeconds()).thenReturn(customMaxAge);
        OAuthEntryPointServlet servletWithCustomConfig = new OAuthEntryPointServlet(
                Arrays.asList(MockOidcConnection.DEFAULT_CONNECTION), new StubCryptoService(), config);

        context.request().setQueryString("c=" + MockOidcConnection.DEFAULT_CONNECTION.name());
        MockSlingHttpServletResponse response = context.response();

        servletWithCustomConfig.service(context.request(), response);

        Cookie requestKeyCookie = Arrays.stream(response.getCookies())
                .filter(c -> OAuthCookieValue.COOKIE_NAME_REQUEST_KEY.equals(c.getName()))
                .findFirst()
                .orElseThrow();
        assertEquals(customMaxAge, requestKeyCookie.getMaxAge());
    }
}
