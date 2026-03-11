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

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.servlet.http.HttpServletRequest;

import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.jcr.api.SlingRepository;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles OIDC logout operations including IdP session termination.
 * This class encapsulates the logic for SP-initiated single logout as defined by the
 * OIDC RP-Initiated Logout specification.
 */
class OidcLogoutHandler {

    private static final Logger logger = LoggerFactory.getLogger(OidcLogoutHandler.class);
    private static final String ROOT_PATH = "/";

    private final SlingRepository repository;
    private final CryptoService cryptoService;
    private final OAuthTokenStore tokenStore;
    private final Map<String, ClientConnection> connections;
    private final String defaultConnectionName;
    private final String logoutServiceUserName;
    private final String logoutRedirectPath;
    private final Set<String> logoutRedirectAllowedHosts;

    @SuppressWarnings("java:S107")
    OidcLogoutHandler(
            @NotNull SlingRepository repository,
            @NotNull CryptoService cryptoService,
            @Nullable OAuthTokenStore tokenStore,
            @NotNull Map<String, ClientConnection> connections,
            @NotNull String defaultConnectionName,
            @NotNull String logoutServiceUserName,
            @NotNull String logoutRedirectPath,
            @NotNull Set<String> logoutRedirectAllowedHosts) {
        this.repository = repository;
        this.cryptoService = cryptoService;
        this.tokenStore = tokenStore;
        this.connections = connections;
        this.defaultConnectionName = defaultConnectionName;
        this.logoutServiceUserName = logoutServiceUserName;
        this.logoutRedirectPath = logoutRedirectPath;
        this.logoutRedirectAllowedHosts = logoutRedirectAllowedHosts;
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
    String buildPostLogoutRedirectUri(HttpServletRequest request, @Nullable String redirectParameter) {
        // Try to use the redirect parameter if provided and valid
        if (redirectParameter != null && !redirectParameter.isEmpty()) {
            String validatedRedirect = validateAndBuildRedirectFromParameter(redirectParameter, request);
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
            @NotNull String redirectParameter, @NotNull HttpServletRequest request) {
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
     * @return the client connection, or null if none available
     */
    @Nullable
    ClientConnection resolveConnectionForLogout() {
        if (defaultConnectionName != null && !defaultConnectionName.isEmpty()) {
            ClientConnection connection = connections.get(defaultConnectionName);
            if (connection != null) {
                return connection;
            }
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
     * Reads the id_token from the user's OAK profile using a service account, for use as id_token_hint
     * at the IdP end_session_endpoint. The token must have been stored previously (e.g. by
     * SlingUserInfoProcessorImpl with storeIdToken and the sync layer persisting credentials to OAK).
     * <p>
     * The service user configured via logoutServiceUserName must be configured in Apache Jackrabbit Oak
     * (e.g. system users / External Principal Configuration) with minimal read-only access to user profile
     * properties. DO NOT grant write or administrative permissions to this service user.
     *
     * @param userId the current user id (e.g. from request.getRemoteUser())
     * @return the id_token string, or null if not found or on error
     */
    @Nullable
    String getIdTokenFromOak(@NotNull String userId) {
        Session serviceSession = null;
        try {
            serviceSession = repository.loginService(logoutServiceUserName, null);
            if (serviceSession == null) {
                logger.warn(
                        "Service session is null for user '{}'. Verify service user mapping is configured.",
                        logoutServiceUserName);
                return null;
            }

            // Use tokenStore if available, otherwise fall back to legacy implementation
            if (tokenStore != null) {
                ClientConnection connection = resolveConnectionForLogout();
                if (connection != null) {
                    return tokenStore.getIdToken(connection, serviceSession, userId);
                } else {
                    logger.debug("No connection available for retrieving id_token for user {}", userId);
                    return null;
                }
            } else {
                // Legacy fallback when tokenStore is not available
                UserManager um = ((JackrabbitSession) serviceSession).getUserManager();
                Authorizable authorizable = um.getAuthorizable(userId);
                if (authorizable == null || authorizable.isGroup()) {
                    logger.debug("User {} not found or is a group; cannot read id_token from OAK", userId);
                    return null;
                }
                return readAndDecryptIdToken(authorizable, userId);
            }
        } catch (RepositoryException e) {
            logger.error(
                    "Repository error reading id_token for user {}. Verify service user '{}' has read access to user profiles. Error: {}",
                    userId,
                    logoutServiceUserName,
                    e.getMessage(),
                    e);
            return null;
        } finally {
            if (serviceSession != null) {
                serviceSession.logout();
            }
        }
    }

    /**
     * Reads the id_token property from the authorizable and decrypts it.
     * Tries both profile/id_token and id_token paths.
     *
     * @param authorizable the user authorizable
     * @param userId the user id (for logging)
     * @return the decrypted id_token, or null if not found or decryption fails
     */
    @Nullable
    private String readAndDecryptIdToken(@NotNull Authorizable authorizable, @NotNull String userId) {
        for (String relPath : new String[] {
            OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN,
            OAuthTokenStore.PROPERTY_NAME_ID_TOKEN
        }) {
            try {
                if (authorizable.hasProperty(relPath)) {
                    Value[] values = authorizable.getProperty(relPath);
                    if (values != null && values.length > 0) {
                        String encrypted = values[0].getString();
                        if (encrypted != null && !encrypted.isEmpty()) {
                            return decryptIdToken(encrypted, userId);
                        }
                    }
                }
            } catch (RepositoryException e) {
                logger.warn("Error reading property {} for user {}: {}", relPath, userId, e.getMessage());
            }
        }
        logger.debug("No id_token found on user {} in OAK (storeIdToken and sync must persist it)", userId);
        return null;
    }

    /**
     * Decrypts the encrypted id_token value.
     *
     * @param encrypted the encrypted id_token
     * @param userId the user id (for logging)
     * @return the decrypted id_token, or null if decryption fails
     */
    @Nullable
    private String decryptIdToken(@NotNull String encrypted, @NotNull String userId) {
        try {
            String decrypted = cryptoService.decrypt(encrypted);
            logger.debug("Successfully retrieved and decrypted id_token for user {}", userId);
            return decrypted;
        } catch (Exception e) {
            logger.error(
                    "Failed to decrypt id_token for user {}. IdP may not properly invalidate session. Error: {}",
                    userId,
                    e.getMessage(),
                    e);
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
