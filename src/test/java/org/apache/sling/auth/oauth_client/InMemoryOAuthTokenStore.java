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

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.apache.sling.api.resource.ResourceResolver;

/**
 * In-memory, volatile token store implementation
 * 
 * <p>This implementation exists for testing purposes only</p>
 */
public class InMemoryOAuthTokenStore implements OAuthTokenStore {
    
    record Key(String connectionName, String userId) {}

    record Value(OAuthTokens tokens, Instant expires) {
        
        public Value(OAuthTokens tokens) {
            this(tokens, tokens.expiresAt() != 0 ? Instant.now().plusSeconds(tokens.expiresAt()) : null);
        }
        
        public boolean isValid() {
            return expires == null || expires.isAfter(Instant.now());
        }
        
    }
    
    private final Map<Key, Value> storage = new HashMap<>();

    @Override
    public void persistTokens(ClientConnection connection, ResourceResolver resolver, OAuthTokens tokens)
            throws OAuthException {
        storage.put(new Key(connection.name(), resolver.getUserID()), new Value(tokens));
    }

    @Override
    public OAuthToken getRefreshToken(ClientConnection connection, ResourceResolver resolver) throws OAuthException {
        Value value = storage.get(new Key(connection.name(), resolver.getUserID()));
        if (value == null || value.tokens == null || value.tokens.refreshToken() == null)
            return new OAuthToken(TokenState.MISSING, null);
        
        return new OAuthToken(TokenState.VALID, value.tokens.refreshToken());
    }

    @Override
    public OAuthToken getAccessToken(ClientConnection connection, ResourceResolver resolver) throws OAuthException {
        Value value = storage.get(new Key(connection.name(), resolver.getUserID()));
        if (value == null || value.tokens == null || value.tokens.accessToken() == null )
            return new OAuthToken(TokenState.MISSING, null);
        
        if (!value.isValid())
            return new OAuthToken(TokenState.EXPIRED, value.tokens.accessToken());
        
        return new OAuthToken(TokenState.VALID, value.tokens.accessToken());
        
    }

    @Override
    public void clearAccessToken(ClientConnection connection, ResourceResolver resolver) throws OAuthException {
        Key key = new Key(connection.name(), resolver.getUserID());
        Value value = storage.get(key);
        
        // preserve the refresh token is present
        if ( value != null && value.tokens != null && value.tokens.refreshToken() != null ) {
            OAuthTokens newTokens = new OAuthTokens(null, 0, value.tokens.refreshToken());
            storage.put(key, new Value(newTokens));
        // remover all tokens if only the access token is present
        } else if ( value != null ) {
            storage.remove(key);
        }
    }
    
    public Stream<OAuthTokens> allTokens() {
        return storage.values().stream().map(Value::tokens);
    }
}