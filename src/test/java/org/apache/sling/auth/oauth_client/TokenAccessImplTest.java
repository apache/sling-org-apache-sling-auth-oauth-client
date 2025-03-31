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
package org.apache.sling.auth.oauth_client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.apache.sling.auth.oauth_client.impl.MockOidcConnection;
import org.apache.sling.auth.oauth_client.impl.OAuthTokenRefresher;
import org.apache.sling.auth.oauth_client.spi.OAuthTokenStore;
import org.apache.sling.auth.oauth_client.spi.OAuthTokens;
import org.apache.sling.auth.oauth_client.impl.TokenAccessImpl;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

@ExtendWith(SlingContextExtension.class)
class TokenAccessImplTest {
    
    private SlingContext slingContext = new SlingContext();

    @Test
    void missingAccessToken() {
        
        OAuthTokenStore tokenStore = new InMemoryOAuthTokenStore();
        
        TokenAccessImpl tokenAccess = new TokenAccessImpl(tokenStore, null);
        
        OAuthTokenResponse tokenResponse = tokenAccess.getAccessToken(MockOidcConnection.DEFAULT_CONNECTION, slingContext.request(), "/");
        
        assertThat(tokenResponse)
            .as("tokenResponse")
            .isNotNull()
            .satisfies( tr -> {
                assertThat(tr.hasValidToken()).as("hasValidToken").isFalse();
                assertThrows(IllegalStateException.class, tr::getTokenValue, "getTokenValue");
                assertThat(tr.getRedirectUri()).as("redirectUri")
                    .isNotNull()
                    .asString()
                    .isNotBlank();
            });
    }
    
    @Test
    void presentAccessToken() {
        OAuthTokenStore tokenStore = new InMemoryOAuthTokenStore();

        TokenAccessImpl tokenAccess = new TokenAccessImpl(tokenStore, null);
        
        tokenStore.persistTokens(MockOidcConnection.DEFAULT_CONNECTION, slingContext.resourceResolver(), new OAuthTokens("access", 0, null));
        
        OAuthTokenResponse tokenResponse = tokenAccess.getAccessToken(MockOidcConnection.DEFAULT_CONNECTION, slingContext.request(), "/");
        
        assertThat(tokenResponse)
            .as("tokenResponse")
            .isNotNull()
            .satisfies( tr -> {
                assertThat(tr.hasValidToken()).as("hasValidToken").isTrue();
                assertThat(tr.getTokenValue()).as("tokenValue").isEqualTo("access");
                assertThrows(IllegalStateException.class, tr::getRedirectUri, "getRedirectUri");
            });
    }
    
    @Test
    void refreshTokenUsed() {
        
        OAuthTokens expiredTokens = new OAuthTokens("access", -1, "refresh");
        OAuthTokens refreshedTokens = new OAuthTokens("access2", 0, null);
        
        OAuthTokenStore tokenStore = new InMemoryOAuthTokenStore();
        
        OAuthTokenRefresher tokenRefresher = new OAuthTokenRefresher() {
            @Override
            public OAuthTokens refreshTokens(ClientConnection connection, String refreshToken) {
                if (!refreshToken.equals(expiredTokens.refreshToken()))
                    throw new IllegalArgumentException("Invalid refresh token");
                
                return refreshedTokens;
            }
        };

        TokenAccessImpl tokenAccess = new TokenAccessImpl(tokenStore, tokenRefresher);

        tokenStore.persistTokens(MockOidcConnection.DEFAULT_CONNECTION, slingContext.resourceResolver(), expiredTokens);
        
        OAuthTokenResponse tokenResponse = tokenAccess.getAccessToken(MockOidcConnection.DEFAULT_CONNECTION, slingContext.request(), "/");
        
        assertThat(tokenResponse)
            .as("tokenResponse")
            .isNotNull()
            .satisfies( tr -> {
                assertThat(tr.hasValidToken()).as("hasValidToken").isTrue();
                assertThat(tr.getTokenValue()).as("tokenValue").isEqualTo(refreshedTokens.accessToken());
                assertThrows(IllegalStateException.class, tr::getRedirectUri, "getRedirectUri");
            });
    }
    
    @Test
    void clearAccessTokenWithResponse() {
        
        OAuthTokenStore tokenStore = new InMemoryOAuthTokenStore();

        TokenAccessImpl tokenAccess = new TokenAccessImpl(tokenStore, null);
        
        tokenStore.persistTokens(MockOidcConnection.DEFAULT_CONNECTION, slingContext.resourceResolver(), new OAuthTokens("access", 0, null));

        OAuthTokenResponse okResponse = tokenAccess.getAccessToken(MockOidcConnection.DEFAULT_CONNECTION, slingContext.request(), "/");
        assertThat(okResponse.hasValidToken()).isTrue();
        
        OAuthTokenResponse clearResponse = tokenAccess.clearAccessToken(MockOidcConnection.DEFAULT_CONNECTION, slingContext.request(), "/");
        
        assertThat(clearResponse)
            .as("tokenResponse after clear")
            .isNotNull()
            .extracting(OAuthTokenResponse::hasValidToken)
            .isEqualTo(false);
    }
    
    @Test
    void clearAccessTokenWithoutResponse() {
        
        InMemoryOAuthTokenStore tokenStore = new InMemoryOAuthTokenStore();

        TokenAccessImpl tokenAccess = new TokenAccessImpl(tokenStore, null);
        
        tokenStore.persistTokens(MockOidcConnection.DEFAULT_CONNECTION, slingContext.resourceResolver(), new OAuthTokens("access", 0, null));

        OAuthTokenResponse okResponse = tokenAccess.getAccessToken(MockOidcConnection.DEFAULT_CONNECTION, slingContext.request(), "/");
        assertThat(okResponse.hasValidToken()).isTrue();
        
        tokenAccess.clearAccessToken(MockOidcConnection.DEFAULT_CONNECTION, slingContext.resourceResolver());
        
        assertThat(tokenStore.allTokens())
            .as("all persisted tokens")
            .isEmpty();
    }

}
