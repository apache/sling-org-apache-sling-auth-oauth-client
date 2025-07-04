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

import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

// TODO - bad name
@Component
@Designate(ocd = OAuthConnectionImpl.Config.class, factory = true)
public class OAuthConnectionImpl implements ClientConnection {

    @ObjectClassDefinition(name = "OAuth connection details")
    public @interface Config {
        String name();

        String authorizationEndpoint();

        String tokenEndpoint();

        String clientId();

        @AttributeDefinition(type = AttributeType.PASSWORD)
        String clientSecret();

        String[] scopes();

        String[] additionalAuthorizationParameters();

        String webconsole_configurationFactory_nameHint() default
                "Name: {name}, auth endpoint: {authorizationEndpoint}, clientId: {clientId}";
    }

    private final Config cfg;

    @Activate
    public OAuthConnectionImpl(@NotNull Config cfg) {
        this.cfg = cfg;
    }

    @Override
    public @NotNull String name() {
        return cfg.name();
    }

    public @NotNull String authorizationEndpoint() {
        return cfg.authorizationEndpoint();
    }

    public @NotNull String tokenEndpoint() {
        return cfg.tokenEndpoint();
    }

    public @NotNull String clientId() {
        return cfg.clientId();
    }

    public @Nullable String clientSecret() {
        return cfg.clientSecret();
    }

    public @NotNull String[] scopes() {
        return cfg.scopes();
    }

    public @NotNull String[] additionalAuthorizationParameters() {
        return cfg.additionalAuthorizationParameters();
    }
}
