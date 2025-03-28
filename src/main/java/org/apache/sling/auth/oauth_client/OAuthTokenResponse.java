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

import java.net.URI;
import java.util.Optional;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.auth.oauth_client.impl.OAuthUris;
import org.jetbrains.annotations.NotNull;

/**
 * Encapsulates the response to a token request.
 * 
 * <p>This class has two top-level states:</p>
 * <ol>
 *   <li>has a valid access token: {@link #hasValidToken()} returns {@code true}, and {@link #getTokenValue()} returns the token value.</li>
 *   <li>does not have a valid access token: {@link #hasValidToken()} returns {@code false}, and {@link #getRedirectUri()} returns the URI to redirect the user to.</li>
 * </ol>
 * 
 * <p>Methods generally throw {@link IllegalStateException} if they are called in an unexpected state and do not return null values.</p>
 */
@NotNull
public class OAuthTokenResponse {
    
    private final Optional<String> token;
    private final ClientConnection connection;
    private final SlingHttpServletRequest request;
    private String redirectPath;
    
    public OAuthTokenResponse(Optional<String> token, ClientConnection connection, SlingHttpServletRequest request, String redirectPath) {
        this.token = token;
        this.connection = connection;
        this.request = request;
        this.redirectPath = redirectPath;
    }

    /**
     * Returns true if a valid access token is present and false otherwise
     * 
     * @return true if a valid access token is present
     */
    public boolean hasValidToken() {
        return token.isPresent();
    }
    
    
    /**
     * Returns the a valid access token value and throws an {@link IllegalStateException} otherwise
     * 
     * @return a valid access token value
     * @throws IllegalStateException if no access token is present
     */
    public String getTokenValue() {
        return token.orElseThrow(() -> new IllegalStateException("No access token present."));
    }
    
    /**
     * Returns the URI to redirect the user to in order to start the OAuth flow
     * 
     * @return the URI to redirect the user to
     * @throws IllegalStateException if an access token is present
     */
    public URI getRedirectUri() {
        if ( token.isPresent() )
            throw new IllegalStateException("Access token is present, will not generate a new redirect URI.");
        
        return OAuthUris.getOAuthEntryPointUri(connection, request, redirectPath);
    }
}