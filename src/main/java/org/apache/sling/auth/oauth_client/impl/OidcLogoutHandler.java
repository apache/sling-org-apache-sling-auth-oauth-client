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

import javax.servlet.http.HttpServletRequest;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles OIDC logout operations including IdP session termination.
 * This class encapsulates the logic for SP-initiated single logout as defined by the
 * OIDC RP-Initiated Logout specification.
 */
@Component(service = OidcLogoutHandler.class)
public class OidcLogoutHandler {

    private static final Logger logger = LoggerFactory.getLogger(OidcLogoutHandler.class);
    private static final String ROOT_PATH = "/";

    private final OAuthTokenStore tokenStore;

    @Activate
    public OidcLogoutHandler(
            @Reference(cardinality = ReferenceCardinality.OPTIONAL, policyOption = ReferencePolicyOption.GREEDY)
                    OAuthTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    /**
     * Builds the post_logout_redirect_uri sent to the IdP. When logoutRedirectAllowedHosts is set,
     * the resulting URI's host is validated to prevent open redirect (Host header spoofing); if not allowed,
     * the first allowed host is used instead.
     *
     * @param request the HTTP request
     * @param redirectParameter optional redirect parameter from the request (e.g., query parameter)
     * @return the post-logout redirect URI
     */
    @NotNull
    String buildPostLogoutRedirectUri(
            HttpServletRequest request,
            @Nullable String redirectParameter,
            @NotNull String logoutRedirectPath,
            @NotNull Set<String> logoutRedirectAllowedHosts) {
        // Try to use the redirect parameter if provided and valid
        if (redirectParameter != null && !redirectParameter.isEmpty()) {
            String validatedRedirect =
                    validateAndBuildRedirectFromParameter(redirectParameter, request, logoutRedirectAllowedHosts);
            if (validatedRedirect != null) {
                return validatedRedirect;
            }
            // If validation failed, fall through to use configured logoutRedirectPath
            logger.debug(
                    "Redirect parameter '{}' failed validation; falling back to configured logoutRedirectPath",
                    redirectParameter);
        }

        // Use configured logoutRedirectPath
        String redirectPath = logoutRedirectPath;
        if (redirectPath == null || redirectPath.isEmpty()) {
            redirectPath = ROOT_PATH;
        }
        if (!redirectPath.startsWith(ROOT_PATH)) {
            redirectPath = ROOT_PATH + redirectPath;
        }
        // Note: Context path handling omitted - Sling always deploys at root context ("/")
        int port = request.getServerPort();
        String scheme = request.getScheme();
        String host = request.getServerName();

        // Validate host against allow list (guaranteed non-empty when SP-initiated logout is enabled)
        // This prevents Host header spoofing attacks
        try {
            String hostLower = host.toLowerCase();
            if (!logoutRedirectAllowedHosts.contains(hostLower)) {
                String safeHost = logoutRedirectAllowedHosts.iterator().next();
                logger.debug(
                        "Post-logout redirect host '{}' not in allowed list; using '{}' to prevent open redirect",
                        host,
                        safeHost);
                host = safeHost;
            }
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid redirect URI for logout: {}", e.getMessage());
            // Fall back to first allowed host
            host = logoutRedirectAllowedHosts.iterator().next();
        }

        return UriBuilder.buildRedirectUri(scheme, host, port, redirectPath);
    }

    /**
     * Validates the redirect parameter and builds a full redirect URI if valid.
     * The redirect parameter MUST be a relative path (starting with "/" but not "//").
     * Absolute URLs are rejected for security reasons to prevent open redirect vulnerabilities.
     * The relative path is converted to an absolute URL using the request's scheme/host/port.
     *
     * @param redirectParameter the redirect parameter value (must be a relative path)
     * @param request the HTTP request
     * @return the validated redirect URI, or null if validation fails
     */
    @Nullable
    private String validateAndBuildRedirectFromParameter(
            @NotNull String redirectParameter,
            @NotNull HttpServletRequest request,
            @NotNull Set<String> logoutRedirectAllowedHosts) {
        try {
            // Validate that it's a relative path, not an absolute URL
            // Must start with "/" but not "//" (which could be a protocol-relative URL)
            if (!redirectParameter.startsWith("/") || redirectParameter.startsWith("//")) {
                logger.debug(
                        "Redirect parameter '{}' is not a valid relative path (must start with / but not //); rejecting",
                        redirectParameter);
                return null;
            }

            // Parse to ensure it's a valid URI structure
            URI uri = new URI(redirectParameter);

            // Reject if it's an absolute URI (has scheme)
            if (uri.isAbsolute()) {
                logger.debug(
                        "Redirect parameter '{}' is an absolute URL; only relative paths are allowed; rejecting",
                        redirectParameter);
                return null;
            }

            // Get the path component
            String path = uri.getPath();
            if (path == null || path.isEmpty()) {
                logger.debug("Redirect parameter '{}' has no path; rejecting", redirectParameter);
                return null;
            }

            // Build absolute URL from relative path
            // Note: Context path handling omitted - Sling always deploys at root context ("/")
            String scheme = request.getScheme();
            String host = request.getServerName();
            int port = request.getServerPort();

            // Validate request host against allow list (guaranteed non-empty when SP-initiated logout is enabled)
            // This prevents Host header spoofing attacks
            String hostLower = host.toLowerCase();
            if (!logoutRedirectAllowedHosts.contains(hostLower)) {
                // Use the first allowed host instead of the request host
                String safeHost = logoutRedirectAllowedHosts.iterator().next();
                logger.debug(
                        "Request host '{}' not in allowed list; using '{}' for redirect parameter", host, safeHost);
                host = safeHost;
            }

            return UriBuilder.buildRedirectUri(scheme, host, port, path);
        } catch (URISyntaxException e) {
            logger.debug(
                    "Redirect parameter '{}' is not a valid URI; rejecting: {}", redirectParameter, e.getMessage());
            return null;
        } catch (IllegalArgumentException e) {
            logger.debug("Failed to build redirect URI from parameter '{}': {}", redirectParameter, e.getMessage());
            return null;
        }
    }

    /**
     * Resolves the client connection to use for logout operations.
     *
     * @param connections map of available connections
     * @param defaultConnectionName preferred connection name (may be empty)
     * @return the client connection, or null if none available
     */
    @Nullable
    static ClientConnection resolveConnectionForLogout(
            @NotNull Map<String, ClientConnection> connections, @Nullable String defaultConnectionName) {
        if (defaultConnectionName != null && !defaultConnectionName.isEmpty()) {
            return connections.get(defaultConnectionName);
        }
        return connections.isEmpty() ? null : connections.values().iterator().next();
    }

    /**
     * Extracts the end_session_endpoint from the OIDC connection.
     *
     * @param connection the client connection
     * @return the end session endpoint URI, or null if not available
     */
    @Nullable
    URI getEndSessionEndpoint(@NotNull ClientConnection connection) {
        if (connection instanceof OidcConnectionImpl) {
            return ((OidcConnectionImpl) connection).endSessionEndpoint();
        }
        return null;
    }

    /**
     * Reads the id_token for the current user, for use as id_token_hint at the IdP end_session_endpoint.
     *
     * @param resolver the resource resolver for the current user
     * @param connection the resolved client connection to use with the token store
     * @return the id_token string, or null if not found or on error
     */
    @Nullable
    String getIdTokenFromOak(@Nullable ResourceResolver resolver, @Nullable ClientConnection connection) {
        if (tokenStore == null || resolver == null || connection == null) {
            return null;
        }
        try {
            return tokenStore.getIdToken(connection, resolver);
        } catch (OAuthException e) {
            logger.warn("Error reading id_token for user '{}': {}", resolver.getUserID(), e.getMessage(), e);
            return null;
        }
    }

    /**
     * Builds the logout URL with OIDC RP-Initiated Logout parameters.
     *
     * @param endSessionEndpoint the IdP's end_session_endpoint
     * @param postLogoutRedirectUri where to redirect after logout
     * @param idTokenHint the ID token to use as hint (optional)
     * @return the complete logout URL
     */
    @NotNull
    static String buildLogoutUrl(
            @NotNull URI endSessionEndpoint, @NotNull String postLogoutRedirectUri, @Nullable String idTokenHint) {
        String encodedRedirect = URLEncoder.encode(postLogoutRedirectUri, StandardCharsets.UTF_8);
        String endSessionStr = endSessionEndpoint.toString();
        StringBuilder sb = new StringBuilder(endSessionStr).append(endSessionStr.contains("?") ? "&" : "?");
        if (idTokenHint != null && !idTokenHint.isEmpty()) {
            sb.append("id_token_hint=")
                    .append(URLEncoder.encode(idTokenHint, StandardCharsets.UTF_8))
                    .append("&");
        }
        sb.append("post_logout_redirect_uri=").append(encodedRedirect);
        return sb.toString();
    }

    /**
     * Helper class for building URIs.
     */
    static class UriBuilder {

        private UriBuilder() {}

        /**
         * Builds a redirect URI string from components.
         *
         * @param scheme the URI scheme (http/https)
         * @param host the hostname
         * @param port the port number
         * @param path the path component
         * @return the constructed URI string
         * @throws IllegalArgumentException if the URI is invalid
         */
        @NotNull
        static String buildRedirectUri(@NotNull String scheme, @NotNull String host, int port, @Nullable String path) {
            if (scheme.isEmpty()) {
                throw new IllegalArgumentException("Scheme cannot be empty");
            }
            if (host.isEmpty()) {
                throw new IllegalArgumentException("Host cannot be empty");
            }
            if (path == null) {
                path = ROOT_PATH;
            }

            boolean defaultPort = (scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443);
            StringBuilder sb = new StringBuilder();
            sb.append(scheme).append("://").append(host);
            if (!defaultPort) {
                sb.append(':').append(port);
            }
            sb.append(path);

            // Validate the constructed URI
            String uriString = sb.toString();
            try {
                URI.create(uriString);
            } catch (IllegalArgumentException e) {
                throw new IllegalArgumentException("Invalid redirect URI constructed: " + uriString, e);
            }
            return uriString;
        }
    }
}
