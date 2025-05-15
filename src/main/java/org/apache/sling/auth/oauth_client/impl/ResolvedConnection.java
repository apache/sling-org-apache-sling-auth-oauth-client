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

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.List;

abstract class ResolvedConnection {
    
    private final String name;
    private final String authorizationEndpoint;
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final List<String> scopes;
    private final List<String> additionalAuthorizationParameters;

    ResolvedConnection(@NotNull String name, @NotNull String authorizationEndpoint, @NotNull String tokenEndpoint, @NotNull String clientId,
                       @Nullable String clientSecret, @NotNull List<String> scopes, @NotNull List<String> additionalAuthorizationParameters) {
        this.name = name;
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.scopes = scopes;
        this.additionalAuthorizationParameters = additionalAuthorizationParameters;
    }


    public @NotNull String name() {
        return name;
    }

    public @NotNull String authorizationEndpoint() {
        return authorizationEndpoint;
    }

    public @NotNull String tokenEndpoint() {
        return tokenEndpoint;
    }

    public @NotNull String clientId() {
        return clientId;
    }

    public @Nullable String clientSecret() {
        return clientSecret;
    }

    public @NotNull List<String> scopes() {
        return scopes;
    }

    public @NotNull List<String> additionalAuthorizationParameters() {
        return additionalAuthorizationParameters;
    }
}
