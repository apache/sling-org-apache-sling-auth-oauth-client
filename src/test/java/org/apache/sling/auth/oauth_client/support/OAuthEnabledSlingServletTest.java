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
package org.apache.sling.auth.oauth_client.support;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;

import javax.servlet.ServletException;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.InMemoryOAuthTokenStore;
import org.apache.sling.auth.oauth_client.OAuthTokenAccess;
import org.apache.sling.auth.oauth_client.impl.MockOidcConnection;
import org.apache.sling.auth.oauth_client.impl.OAuthException;
import org.apache.sling.auth.oauth_client.impl.OAuthTokenRefresher;
import org.apache.sling.auth.oauth_client.impl.OAuthTokenStore;
import org.apache.sling.auth.oauth_client.impl.OAuthTokens;
import org.apache.sling.auth.oauth_client.impl.TokenAccessImpl;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(SlingContextExtension.class)
class OAuthEnabledSlingServletTest {

    private SlingContext context = new SlingContext();
    private TokenAccessImpl tokenAccess;
    private InMemoryOAuthTokenStore tokenStore;
    
    @BeforeEach
    void initServices() {
        tokenStore = (InMemoryOAuthTokenStore) context.registerService(OAuthTokenStore.class, new InMemoryOAuthTokenStore());
        context.registerService(OAuthTokenRefresher.class, new OAuthTokenRefresher() {
            @Override
            public @NotNull OAuthTokens refreshTokens(@NotNull ClientConnection connection, @NotNull String refreshToken) throws OAuthException {
                throw new UnsupportedOperationException("Not yet implemented");
            }
        });
        
        tokenAccess = context.registerInjectActivateService(TokenAccessImpl.class);
    }
    
    @Test
    void errorWhenUserIsNotLoggedIn() throws ServletException, IOException {
        
        OAuthEnabledSlingServletTestImpl servlet = new OAuthEnabledSlingServletTestImpl(MockOidcConnection.DEFAULT_CONNECTION, tokenAccess);
        
        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response status code").isEqualTo(401);
    }

    
    @Test
    void redirectWhenNoTokenIsFound() throws ServletException, IOException {
        
        context.request().setRemoteUser("user");

        OAuthEnabledSlingServletTestImpl servlet = new OAuthEnabledSlingServletTestImpl(MockOidcConnection.DEFAULT_CONNECTION, tokenAccess);
        
        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response status code").isEqualTo(302);
        assertThat(context.response().getHeader("location")).as("redirect location").startsWith("http://localhost/system/sling/oauth/entry-point");
    }
    
    @Test
    void doGetInvokedWhenTokenIsFound() throws ServletException, IOException {
        
        doInvokeWithToken("GET", "Hello World. GET. TOKEN: ACCESS_TOKEN");
    }
    
    @Test
    void doPostInvokedWhenTokenIsFound() throws ServletException, IOException {
        
        doInvokeWithToken("POST", "Hello World. POST. TOKEN: ACCESS_TOKEN");
    }

    @Test
    void doPutInvokedWhenTokenIsFound() throws ServletException, IOException {
        
        doInvokeWithToken("PUT", "Hello World. PUT. TOKEN: ACCESS_TOKEN");
    }
    
    @Test
    void doDeleteInvokedWhenTokenIsFound() throws ServletException, IOException {
        
        doInvokeWithToken("DELETE", "Hello World. DELETE. TOKEN: ACCESS_TOKEN");
    }
    
    private void doInvokeWithToken(String method, String expectedBody) throws ServletException, IOException {
        context.request().setRemoteUser("user");
        
        tokenStore.persistTokens(MockOidcConnection.DEFAULT_CONNECTION, context.resourceResolver(), new OAuthTokens("ACCESS_TOKEN", 0, null));

        OAuthEnabledSlingServletTestImpl servlet = new OAuthEnabledSlingServletTestImpl(MockOidcConnection.DEFAULT_CONNECTION, tokenAccess);
        
        context.request().setMethod(method);
        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response status code").isEqualTo(200);
        assertThat(context.response().getOutputAsString()).as("response body").isEqualTo(expectedBody);
    }
    
    @Test
    void doGenericInvokedWhenTokenIsFound() throws ServletException, IOException {
        
        doInvokeWithToken("PATCH", "Hello World. PATCH. TOKEN: ACCESS_TOKEN");
    }
    
    @Test
    void exceptionClearedAndRedirectIssueWhenTokenIsInvalid() throws ServletException, IOException {
        
        context.request().setRemoteUser("user");
        
        tokenStore.persistTokens(MockOidcConnection.DEFAULT_CONNECTION, context.resourceResolver(), new OAuthTokens("ACCESS_TOKEN", 0, null));

        OAuthEnabledSlingServletTestImpl servlet = new OAuthEnabledSlingServletTestImpl(MockOidcConnection.DEFAULT_CONNECTION, tokenAccess);
        
        context.request().setMethod("ERROR_TOKEN");
        servlet.service(context.request(), context.response());

        assertThat(context.response().getStatus()).as("response status code").isEqualTo(302);
        assertThat(context.response().getHeader("location")).as("redirect location").startsWith("http://localhost/system/sling/oauth/entry-point");
        assertThat(tokenStore.allTokens()).as("all tokens").isEmpty();
    }
    
    @Test
    void exceptionPropagated() {
        
        context.request().setRemoteUser("user");
        
        tokenStore.persistTokens(MockOidcConnection.DEFAULT_CONNECTION, context.resourceResolver(), new OAuthTokens("ACCESS_TOKEN", 0, null));

        OAuthEnabledSlingServletTestImpl servlet = new OAuthEnabledSlingServletTestImpl(MockOidcConnection.DEFAULT_CONNECTION, tokenAccess);
        
        context.request().setMethod("ERROR_GENERIC");
        
        assertThatThrownBy(() -> servlet.service(context.request(), context.response()))
            .isInstanceOf(ServletException.class);
    }
    
    static class OAuthEnabledSlingServletTestImpl extends OAuthEnabledSlingServlet {

        private static final long serialVersionUID = 1L;

        public OAuthEnabledSlingServletTestImpl(ClientConnection connection, OAuthTokenAccess tokenAccess) {
            super(connection, tokenAccess);
        }
        
        @Override
        protected void doGetWithToken(@NotNull SlingHttpServletRequest request,
                @NotNull SlingHttpServletResponse response, String accessToken) throws ServletException, IOException {
            response.getWriter().write("Hello World. GET. TOKEN: " + accessToken);
        }
        
        @Override
        protected void doPostWithToken(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response, String accessToken)
                throws ServletException, IOException {
            response.getWriter().write("Hello World. POST. TOKEN: " + accessToken);
        }
        @Override
        protected void doPutWithToken(@NotNull SlingHttpServletRequest request,
                @NotNull SlingHttpServletResponse response, String accessToken) throws IOException, ServletException {
            response.getWriter().write("Hello World. PUT. TOKEN: " + accessToken);
        }
        
        @Override
        protected void doDeleteWithToken(@NotNull SlingHttpServletRequest request,
                @NotNull SlingHttpServletResponse response, String accessToken) throws IOException, ServletException {
            response.getWriter().write("Hello World. DELETE. TOKEN: " + accessToken);
        }
        @Override
        protected void doGenericWithToken(@NotNull SlingHttpServletRequest request,
                @NotNull SlingHttpServletResponse response, String accessToken) throws IOException, ServletException {
            
            if (request.getMethod().equals("ERROR_TOKEN") )
                throw new ServletException("CLEAR_TOKEN");
            
            if (request.getMethod().equals("ERROR_GENERIC"))
                throw new ServletException();
                
            response.getWriter().write("Hello World. " + request.getMethod() + ". TOKEN: " + accessToken);
        }

        @Override
        protected boolean isInvalidAccessTokenException(Exception e) {
            return "CLEAR_TOKEN".equals(e.getMessage());
        }
    }

}
