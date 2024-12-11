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

import java.util.Optional;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component
public class TokenAccessImpl implements OAuthTokenAccess {
    
    private final Logger logger = LoggerFactory.getLogger(getClass());
    
    private OAuthTokenStore tokenStore;
    private OAuthTokenRefresher tokenRefresher;
    
    @Activate
    public TokenAccessImpl(@Reference OAuthTokenStore tokenStore, @Reference OAuthTokenRefresher tokenRefresher) {
        this.tokenStore = tokenStore;
        this.tokenRefresher = tokenRefresher;
    }
    
    @Override
    public OAuthTokenResponse getAccessToken(ClientConnection connection, SlingHttpServletRequest request, String redirectPath) {
        
        ResourceResolver resolver = request.getResourceResolver();
        
        OAuthToken token = tokenStore.getAccessToken(connection, resolver);
        
        if ( logger.isDebugEnabled() )
            logger.debug("Accessing token for connection {} and user {}", connection.name(), request.getUserPrincipal());
        
        // valid access token present -> return token
        if (token.getState() == TokenState.VALID) {
            if (logger.isDebugEnabled())
                logger.debug("Returning valid access token for connection {} and user {}", connection.name(), request.getUserPrincipal());
            
            return new OAuthTokenResponse(Optional.of(token.getValue()), connection, request, redirectPath);
        }
        
        // expired token but refresh token present -> refresh and return
        if (token.getState() == TokenState.EXPIRED) {
            OAuthToken refreshToken = tokenStore.getRefreshToken(connection, resolver);
            if (refreshToken.getState() == TokenState.VALID) {
                if (logger.isDebugEnabled())
                    logger.debug("Refreshing expired access token for connection {} and user {}", connection.name(), request.getUserPrincipal());

                OAuthTokens newTokens = tokenRefresher.refreshTokens(connection, refreshToken.getValue());
                tokenStore.persistTokens(connection, resolver, newTokens);
                return new OAuthTokenResponse(Optional.of(newTokens.accessToken()), connection, request, redirectPath);
            }
        }

        // all other scenarios -> redirect
        if ( logger.isDebugEnabled() )
            logger.debug("No valid access token found for connection {} and user {}", connection.name(), request.getUserPrincipal());
        
        return new OAuthTokenResponse(Optional.empty(), connection, request, redirectPath);
    }
    
    @Override
    public OAuthTokenResponse clearAccessToken(ClientConnection connection, SlingHttpServletRequest request, String redirectPath) {
        
        if ( logger.isDebugEnabled() )
            logger.debug("Clearing access token for connection {} and user {}", connection.name(), request.getUserPrincipal());

        tokenStore.clearAccessToken(connection, request.getResourceResolver());
        
        return new OAuthTokenResponse(Optional.empty(), connection, request, redirectPath);
    }
    
    @Override
    public void clearAccessToken(ClientConnection connection, ResourceResolver resolver) {

        if ( logger.isDebugEnabled() )
            logger.debug("Clearing access token for connection {} and user {}", connection.name(), resolver.getUserID());

        tokenStore.clearAccessToken(connection, resolver);
    }
}
