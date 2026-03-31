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

import java.net.URI;
import java.util.Arrays;
import java.util.List;

import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

class ResolvedOidcConnection extends ResolvedConnection {

    private final URI jwkSetURL;
    private final String issuer;
    private final URI endSessionEndpoint;

    /**
     * Constructs a resolved OIDC connection with all parameters materialised.
     *
     * @param name the name of the connection
     * @param authorizationEndpoint the authorization endpoint URL
     * @param tokenEndpoint the token endpoint URL
     * @param clientId the client ID
     * @param clientSecret the client secret, may be null
     * @param scopes the list of scopes
     * @param additionalAuthorizationParameters additional authorization parameters
     * @param jwkSetURL the JWK Set URL, may be null
     * @param issuer the issuer URL
     * @param endSessionEndpoint the end_session endpoint URL for logout, may be null
     */
    private ResolvedOidcConnection(
            @NotNull String name,
            @NotNull String authorizationEndpoint,
            @NotNull String tokenEndpoint,
            @NotNull String clientId,
            @Nullable String clientSecret,
            @NotNull List<String> scopes,
            @NotNull List<String> additionalAuthorizationParameters,
            @Nullable URI jwkSetURL,
            @NotNull String issuer,
            @Nullable URI endSessionEndpoint) {
        super(
                name,
                authorizationEndpoint,
                tokenEndpoint,
                clientId,
                clientSecret,
                scopes,
                additionalAuthorizationParameters);
        this.jwkSetURL = jwkSetURL;
        this.issuer = issuer;
        this.endSessionEndpoint = endSessionEndpoint;
    }

    @Nullable
    URI jwkSetURL() {
        return jwkSetURL;
    }

    @NotNull
    String issuer() {
        return issuer;
    }

    /**
     * Returns the OIDC end_session_endpoint URI for SP-initiated single logout, or null if not available.
     */
    @Nullable
    URI endSessionEndpoint() {
        return endSessionEndpoint;
    }

    static @NotNull ResolvedConnection resolve(@NotNull ClientConnection connection) {
        if (connection instanceof OidcConnectionImpl) {
            OidcConnectionImpl impl = (OidcConnectionImpl) connection;
            return new ResolvedOidcConnection(
                    connection.name(),
                    impl.authorizationEndpoint(),
                    impl.tokenEndpoint(),
                    impl.clientId(),
                    impl.clientSecret(),
                    Arrays.asList(impl.scopes()),
                    Arrays.asList(impl.additionalAuthorizationParameters()),
                    impl.jwkSetURL(),
                    impl.issuer(),
                    impl.endSessionEndpoint());
        }
        throw new IllegalArgumentException(String.format(
                "Unable to resolve %s (name=%s) of type %s",
                ClientConnection.class.getSimpleName(),
                connection.name(),
                connection.getClass().getName()));
    }
}
