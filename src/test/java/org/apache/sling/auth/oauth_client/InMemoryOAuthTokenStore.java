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
import org.apache.sling.auth.oauth_client.impl.OAuthException;
import org.apache.sling.auth.oauth_client.impl.OAuthToken;
import org.apache.sling.auth.oauth_client.impl.OAuthTokenStore;
import org.apache.sling.auth.oauth_client.impl.OAuthTokens;
import org.apache.sling.auth.oauth_client.impl.TokenState;
import org.jetbrains.annotations.NotNull;

/**
 * In-memory, volatile token store implementation
 * 
 * <p>This implementation exists for testing purposes only</p>
 */
public class InMemoryOAuthTokenStore implements OAuthTokenStore {

    public static class Key {
        private final String connectionName;
        private final String userId;

        public Key(String connectionName, String userId) {
            this.connectionName = connectionName;
            this.userId = userId;
        }

        public String getConnectionName() {
            return connectionName;
        }

        public String getUserId() {
            return userId;
        }

        @Override
        public boolean equals(Object obj) {
            if (userId == null) {
                return connectionName.equals(((Key) obj).connectionName);
            }
            if (obj instanceof Key) {
                Key other = (Key) obj;
                return connectionName.equals(other.connectionName) && userId.equals(other.userId);
            }
            return false;
        }

        @Override
        public int hashCode() {
            if (userId == null) {
                return connectionName.hashCode();
            }
            return connectionName.hashCode() + userId.hashCode();
        }
    }

    public static class Value {
        private final OAuthTokens tokens;
        private final Instant expires;

        public Value(OAuthTokens tokens) {
            this.tokens = tokens;
            this.expires = tokens.expiresAt() != 0 ? Instant.now().plusSeconds(tokens.expiresAt()) : null;
        }

        public Value(OAuthTokens tokens, Instant expires) {
            this.tokens = tokens;
            this.expires = expires;
        }

        public OAuthTokens tokens() {
            return tokens;
        }

        public Instant expires() {
            return expires;
        }

        public boolean isValid() {
            return expires == null || expires.isAfter(Instant.now());
        }
    }
    
    private final Map<Key, Value> storage = new HashMap<>();

    @Override
    public void persistTokens(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver, @NotNull OAuthTokens tokens)
            throws OAuthException {
        storage.put(new Key(connection.name(), resolver.getUserID()), new Value(tokens));
    }

    @Override
    public @NotNull OAuthToken getRefreshToken(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver) throws OAuthException {
        Value value = storage.get(new Key(connection.name(), resolver.getUserID()));
        if (value == null || value.tokens == null || value.tokens.refreshToken() == null)
            return new OAuthToken(TokenState.MISSING, null);
        
        return new OAuthToken(TokenState.VALID, value.tokens.refreshToken());
    }

    @Override
    public @NotNull OAuthToken getAccessToken(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver) throws OAuthException {
        Value value = storage.get(new Key(connection.name(), resolver.getUserID()));
        if (value == null || value.tokens == null || value.tokens.accessToken() == null )
            return new OAuthToken(TokenState.MISSING, null);
        
        if (!value.isValid())
            return new OAuthToken(TokenState.EXPIRED, value.tokens.accessToken());
        
        return new OAuthToken(TokenState.VALID, value.tokens.accessToken());
        
    }

    @Override
    public void clearAccessToken(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver) throws OAuthException {
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