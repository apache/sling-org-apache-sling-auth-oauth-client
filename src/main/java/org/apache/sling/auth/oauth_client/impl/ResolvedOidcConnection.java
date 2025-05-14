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

import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;

import java.net.URI;
import java.util.Arrays;
import java.util.List;

public class ResolvedOidcConnection extends ResolvedConnection {

    private final URI jwkSetURL;
    private final String issuer;

    public ResolvedOidcConnection(String name, String authorizationEndpoint, String tokenEndpoint, String clientId,
                                  String clientSecret, List<String> scopes, List<String> additionalAuthorizationParameters,
                                  URI jwkSetURL, String issuer) {
        super(name, authorizationEndpoint, tokenEndpoint, clientId, clientSecret, scopes, additionalAuthorizationParameters);
        this.jwkSetURL = jwkSetURL;
        this.issuer = issuer;
    }

    public URI jwkSetURL() {
        return jwkSetURL;
    }

    public String issuer() {
        return issuer;
    }

    public static @NotNull ResolvedOidcConnection resolve(@NotNull ClientConnection connection) {
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
                    impl.issuer()
            );
        }
        throw new IllegalArgumentException(String.format("Unable to resolve %s (name=%s) of type %s",
                ClientConnection.class.getSimpleName(), connection.name(), connection.getClass().getName()));
    }
}