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

import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.AttributeType;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

// TODO - bad name
@Component
@Designate(ocd = OidcConnectionImpl.Config.class, factory = true)
public class OidcConnectionImpl implements ClientConnection {

    @ObjectClassDefinition(name = "OpenID Connect connection details")
    public @interface Config {
        String name();

        String baseUrl();

        String authorizationEndpoint();

        String tokenEndpoint();

        String userInfoUrl();

        String jwkSetURL();

        String issuer();

        String introspectionEndpoint();

        String clientId();

        @AttributeDefinition(type = AttributeType.PASSWORD)
        String clientSecret();

        String[] scopes();

        String[] additionalAuthorizationParameters();

        String webconsole_configurationFactory_nameHint() default
                "Name: {name}, base URL: {baseUrl}, clientId: {clientId}";
    }

    private final Config cfg;
    private final OidcProviderMetadataRegistry metadataRegistry;
    private final String authorizationEndpoint;
    private final String tokenEndpoint;
    private final String userInfoUrl;
    private final String jwkSetURL;
    private final String issuer;
    private final String introspectionEndpoint;
    private final boolean hasBaseUrl;

    @Activate
    public OidcConnectionImpl(Config cfg, @Reference OidcProviderMetadataRegistry metadataRegistry) {
        this.cfg = cfg;
        this.metadataRegistry = metadataRegistry;
        this.authorizationEndpoint = cfg.authorizationEndpoint();
        this.tokenEndpoint = cfg.tokenEndpoint();
        this.userInfoUrl = cfg.userInfoUrl();
        this.jwkSetURL = cfg.jwkSetURL();
        this.issuer = cfg.issuer();
        this.introspectionEndpoint = cfg.introspectionEndpoint();

        // Validate configuration: either baseUrl is provided OR all explicit endpoints are provided
        hasBaseUrl = !isNullOrEmpty(cfg.baseUrl());

        isValidConfig();
    }

    /**
     * Validate configuration.
     */
    private void isValidConfig() {
        // if baseUrl is provided, no manual configuration parameter must be provided
        if (hasBaseUrl && hasAnyManualConfigurationParameter()) {
            throw new IllegalArgumentException(
                    "Either baseUrl OR explicit endpoints "
                            + "(authorizationEndpoint, tokenEndpoint, userInfoUrl, jwkSetURL, issuer) must be provided, not both");
        }

        // if baseUrl is not provided, all manual configuration parameters must be provided
        if (!hasBaseUrl && !hasAllManualConfigurationParameters()) {
            throw new IllegalArgumentException("Either baseUrl must be provided OR all explicit endpoints "
                    + "(authorizationEndpoint, tokenEndpoint, userInfoUrl, jwkSetURL, issuer) must be provided");
        }
    }

    /**
     * Return true if any manual configuration parameter is provided.
     * @return
     */
    private boolean hasAnyManualConfigurationParameter() {
        return !isNullOrEmpty(tokenEndpoint)
                || !isNullOrEmpty(authorizationEndpoint)
                || !isNullOrEmpty(userInfoUrl)
                || !isNullOrEmpty(jwkSetURL)
                || !isNullOrEmpty(issuer);
    }

    /**
     * Return true if all manual configuration parameters are provided.
     * @return
     */
    private boolean hasAllManualConfigurationParameters() {
        return !isNullOrEmpty(tokenEndpoint)
                && !isNullOrEmpty(authorizationEndpoint)
                && !isNullOrEmpty(userInfoUrl)
                && !isNullOrEmpty(jwkSetURL)
                && !isNullOrEmpty(issuer);
    }
    /**
     * Checks if a string is null or empty.
     *
     * @param str the string to check
     * @return true if the string is null and not empty, false otherwise
     */
    private static boolean isNullOrEmpty(String str) {
        return str == null || str.isEmpty();
    }

    @Override
    public @NotNull String name() {
        return cfg.name();
    }

    public @NotNull String authorizationEndpoint() {
        if (hasBaseUrl) {
            return metadataRegistry.getAuthorizationEndpoint(cfg.baseUrl()).toString();
        }
        return authorizationEndpoint;
    }

    public @NotNull String tokenEndpoint() {
        if (hasBaseUrl) {
            return metadataRegistry.getTokenEndpoint(cfg.baseUrl()).toString();
        }
        return tokenEndpoint;
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

    @Nullable
    String baseUrl() {
        return cfg.baseUrl();
    }

    @NotNull
    String userInfoUrl() {
        if (hasBaseUrl) {
            return metadataRegistry.getUserInfoEndpoint(cfg.baseUrl()).toString();
        }
        return userInfoUrl;
    }

    @NotNull
    URI jwkSetURL() {
        if (hasBaseUrl) {
            return metadataRegistry.getJWKSetURI(cfg.baseUrl());
        }
        return URI.create(jwkSetURL);
    }

    @NotNull
    String issuer() {
        if (hasBaseUrl) {
            return metadataRegistry.getIssuer(cfg.baseUrl());
        }
        return issuer;
    }

    java.net.URI introspectionEndpoint() {
        if (!isNullOrEmpty(introspectionEndpoint)) {
            // Use explicitly configured endpoint
            return java.net.URI.create(introspectionEndpoint);
        }
        if (hasBaseUrl) {
            // Auto-discover from metadata
            return metadataRegistry.getIntrospectionEndpoint(cfg.baseUrl());
        }
        return null; // Not available without baseUrl or explicit config
    }
}
