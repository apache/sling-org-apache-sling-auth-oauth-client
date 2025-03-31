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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.concurrent.TimeUnit;

import org.apache.sling.auth.oauth_client.spi.Converter;
import org.apache.sling.auth.oauth_client.spi.OAuthToken;
import org.apache.sling.auth.oauth_client.spi.OAuthTokenStore;
import org.apache.sling.auth.oauth_client.spi.TokenState;
import org.apache.sling.jackrabbit.usermanager.impl.AuthorizableAdapterFactory;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.apache.sling.testing.mock.sling.junit5.SlingContextExtension;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

/**
 * Support class for testing invariants of {@link OAuthTokenStore} implementations.
 * 
 * @param <T> type of TokenStore to test
 */
@ExtendWith(SlingContextExtension.class)
public abstract class TokenStoreTestSupport<T extends OAuthTokenStore> {

    protected MockOidcConnection connection;
    protected SlingContext context;

    TokenStoreTestSupport(MockOidcConnection connection, SlingContext context) {
        this.connection = connection;
        this.context = context;
    }
    
    abstract @NotNull T createTokenStore();

    @BeforeEach
    public void registerAdapterFactories() {
        context.registerInjectActivateService(new AuthorizableAdapterFactory());
    }
    
    @Test
    void getAccessToken_missing() {
        
        T tokenStore = createTokenStore();
        
        OAuthToken accessToken = tokenStore.getAccessToken(connection, context.resourceResolver());
        
        assertThat(accessToken).as("access token")
            .isNotNull()
            .extracting( OAuthToken::getState )
            .isEqualTo( TokenState.MISSING );
    }
    
    @Test
    void getAccessToken_valid() throws Exception {
        
        OIDCTokens tokens = new OIDCTokens(new BearerAccessToken(12), null);

        T tokenStore = createTokenStore();
        tokenStore.persistTokens(connection, context.resourceResolver(), Converter.toSlingOAuthTokens(tokens));
        
        OAuthToken accessToken = tokenStore.getAccessToken(connection, context.resourceResolver());
        assertThat(accessToken).as("access token")
            .isNotNull()
            .extracting( OAuthToken::getState , OAuthToken::getValue )
            .containsExactly( TokenState.VALID, tokens.getAccessToken().getValue() );
        
        getAccessToken_valid_postCheck(tokens);
    }
    
    protected void getAccessToken_valid_postCheck(OIDCTokens input) throws Exception { 
        // nothing to do by default
    }
    

    @Test
    void getAccessToken_notYetExpired() {
        
        OIDCTokens tokens = new OIDCTokens(new BearerAccessToken(12, 3600, null), null);
        
        T tokenStore = createTokenStore();
        tokenStore.persistTokens(connection, context.resourceResolver(), Converter.toSlingOAuthTokens(tokens));

        OAuthToken accessToken = tokenStore.getAccessToken(connection, context.resourceResolver());
        assertThat(accessToken).as("access token")
            .isNotNull()
            .extracting( OAuthToken::getState )
            .isEqualTo( TokenState.VALID);
    }    

    @Test
    void getAccessToken_expired() throws InterruptedException {
        
        int lifetimeSeconds = 1;
        OIDCTokens tokens = new OIDCTokens(new BearerAccessToken(12, lifetimeSeconds, null), null);
        
        T tokenStore = createTokenStore();
        tokenStore.persistTokens(connection, context.resourceResolver(), Converter.toSlingOAuthTokens(tokens));

        // wait for the token to expire
        Thread.sleep( TimeUnit.SECONDS.toMillis( 2 * lifetimeSeconds ) );
        
        OAuthToken accessToken = tokenStore.getAccessToken(connection, context.resourceResolver());
        assertThat(accessToken).as("access token")
            .isNotNull()
            .extracting( OAuthToken::getState )
            .isIn( TokenState.EXPIRED, TokenState.MISSING ); // TODO - should be EXPIRED but Redis supports only MISSING
            
    }
    
    @Test
    void getRefreshToken_valid() {
        OIDCTokens tokens = new OIDCTokens(new BearerAccessToken(12), new RefreshToken(12));

        T tokenStore = createTokenStore();
        tokenStore.persistTokens(connection, context.resourceResolver(), Converter.toSlingOAuthTokens(tokens));
        
        OAuthToken refreshToken = tokenStore.getRefreshToken(connection, context.resourceResolver());
        assertThat(refreshToken).as("refresh token")
            .isNotNull()
            .extracting( OAuthToken::getState , OAuthToken::getValue )
            .containsExactly( TokenState.VALID, tokens.getRefreshToken().getValue() );
    }
    
    @Test
    void getRefreshToken_missing() {
        
        T tokenStore = createTokenStore();
        
        OAuthToken refreshToken = tokenStore.getRefreshToken(connection, context.resourceResolver());
        assertThat(refreshToken).as("refresh token")
            .isNotNull()
            .extracting( OAuthToken::getState )
            .isEqualTo( TokenState.MISSING);
    }
    
    @Test
    void clearAccessToken() {
        T tokenStore = createTokenStore();
            
        OIDCTokens tokens = new OIDCTokens(new BearerAccessToken(12), null);
        tokenStore.persistTokens(connection, context.resourceResolver(), Converter.toSlingOAuthTokens(tokens));

        assertThat(tokenStore.getAccessToken(connection, context.resourceResolver()))
            .as("persisted access token")
            .isNotNull()
            .extracting( OAuthToken::getState )
            .isEqualTo( TokenState.VALID );

        tokenStore.clearAccessToken(connection, context.resourceResolver());
        
        assertThat(tokenStore.getAccessToken(connection, context.resourceResolver()))
            .as("cleared access token")
            .isNotNull()
            .extracting( OAuthToken::getState )
            .isEqualTo( TokenState.MISSING );
    }
    
    @Test
    void clearAccessToken_missingAlready() {
        T tokenStore = createTokenStore();
        tokenStore.clearAccessToken(connection, context.resourceResolver());
        
        assertThat(tokenStore.getAccessToken(connection, context.resourceResolver()))
            .as("access token")
            .isNotNull()
            .extracting( OAuthToken::getState )
            .isEqualTo( TokenState.MISSING );
    }
}
