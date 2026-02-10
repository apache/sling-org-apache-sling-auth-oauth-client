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
import javax.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.jackrabbit.oak.spi.security.authentication.credentials.CredentialsSupport;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityProvider;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.TokenValidator;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Authentication handler that validates bearer tokens from the Authorization header.
 *
 * <p>This handler extracts bearer tokens from the HTTP Authorization header, validates them
 * using a configured {@link TokenValidator}, and creates authentication credentials for
 * valid tokens.</p>
 *
 * <h2>Features</h2>
 * <ul>
 *   <li>Token validation via pluggable {@link TokenValidator} services</li>
 *   <li>Optional user info fetching from the OIDC UserInfo endpoint</li>
 *   <li>Token caching for improved performance</li>
 *   <li>Integration with {@link UserInfoProcessor} for custom credential creation</li>
 * </ul>
 *
 * @see TokenValidator
 * @see UserInfoProcessor
 * @since 0.1.7
 */
@Component(service = AuthenticationHandler.class, immediate = true)
@Designate(ocd = OidcBearerAuthenticationHandler.Config.class, factory = true)
public class OidcBearerAuthenticationHandler extends DefaultAuthenticationFeedbackHandler
        implements AuthenticationHandler {

    private static final Logger logger = LoggerFactory.getLogger(OidcBearerAuthenticationHandler.class);
    private static final String AUTH_TYPE = "oidc-bearer";
    private static final String BEARER_PREFIX = "Bearer ";

    /**
     * Default HTTP connection timeout in milliseconds.
     */
    private static final int DEFAULT_HTTP_CONNECT_TIMEOUT_MS = 5000;

    /**
     * Default HTTP read timeout in milliseconds.
     */
    private static final int DEFAULT_HTTP_READ_TIMEOUT_MS = 5000;

    @NotNull
    private final Map<String, ClientConnection> connections;

    @NotNull
    private final Map<String, TokenValidator> tokenValidators;

    @NotNull
    private final Map<String, UserInfoProcessor> userInfoProcessors;

    @NotNull
    private final String idp;

    @NotNull
    private final String connectionName;

    @NotNull
    private final String validatorName;

    @NotNull
    private final String[] path;

    private final long cacheTtlSeconds;
    private final int cacheMaxSize;
    private final boolean fetchUserInfo;
    private final int httpConnectTimeoutMs;
    private final int httpReadTimeoutMs;

    // Cache structure: token -> CachedToken
    @NotNull
    private final Map<String, CachedToken> tokenCache = new ConcurrentHashMap<>();

    @ObjectClassDefinition(
            name = "Apache Sling OIDC Bearer Authentication Handler",
            description = "Authentication handler for validating OIDC bearer tokens from Authorization header")
    @interface Config {
        @AttributeDefinition(
                name = "Path",
                description =
                        "Repository path for which this authentication handler should be used by Sling. If this is "
                                + "empty, the authentication handler will be disabled. By default this is set to \"/\".")
        @NotNull
        String[] path() default {"/"};

        @AttributeDefinition(
                name = "Sync Handler Configuration Name",
                description = "Name of Sync Handler Configuration")
        @NotNull
        String idp() default "oidc-bearer";

        @AttributeDefinition(
                name = "Connection Name",
                description =
                        "Name of the OIDC connection to use for bearer token validation. REQUIRED: Must be configured with a valid connection name.")
        @NotNull
        String connectionName();

        @AttributeDefinition(
                name = "Token Validator Name",
                description =
                        "Name of the token validator service to use for token validation. REQUIRED: Must be configured with a valid validator name (e.g., an OfflineTokenValidator or OnlineTokenValidator instance).")
        @NotNull
        String validatorName();

        @AttributeDefinition(
                name = "Fetch User Info",
                description =
                        "Enable fetching user information from the UserInfo endpoint after token validation. When enabled, the user profile will be synchronized with the identity provider. This requires the token to have the appropriate scope (e.g., 'profile').")
        boolean fetchUserInfo() default false;

        @AttributeDefinition(
                name = "Cache TTL (seconds)",
                description =
                        "Time to live for cached tokens in seconds. Default is 300 (5 minutes). Set to 0 to disable caching.")
        long cacheTtlSeconds() default 300;

        @AttributeDefinition(
                name = "Cache Max Size",
                description = "Maximum number of tokens to cache. Default is 1000.")
        int cacheMaxSize() default 1000;

        @AttributeDefinition(
                name = "HTTP Connect Timeout (ms)",
                description =
                        "Timeout in milliseconds for establishing HTTP connections (e.g., to UserInfo endpoint). Default: 5000ms.")
        int httpConnectTimeoutMs() default 5000;

        @AttributeDefinition(
                name = "HTTP Read Timeout (ms)",
                description =
                        "Timeout in milliseconds for reading HTTP responses (e.g., from UserInfo endpoint). Default: 5000ms.")
        int httpReadTimeoutMs() default 5000;

        @AttributeDefinition(name = "Service Ranking", description = "Service ranking for this authentication handler")
        int service_ranking() default 0;
    }

    /**
     * Gets the configured connection.
     *
     * @return the connection to use, or {@code null} if not found
     */
    @Nullable
    private ClientConnection getConnection() {
        return connections.get(connectionName);
    }

    /**
     * Activates the bearer authentication handler with the given configuration.
     *
     * @param bundleContext the OSGi bundle context
     * @param connections the available client connections
     * @param tokenValidators the available token validators
     * @param userInfoProcessors the available user info processors
     * @param config the OSGi configuration
     * @throws IllegalArgumentException if the configuration is invalid
     */
    @Activate
    public OidcBearerAuthenticationHandler(
            @NotNull BundleContext bundleContext,
            @NotNull @Reference List<ClientConnection> connections,
            @NotNull @Reference List<TokenValidator> tokenValidators,
            @NotNull @Reference(policyOption = ReferencePolicyOption.GREEDY) List<UserInfoProcessor> userInfoProcessors,
            @NotNull Config config) {

        this.connections = connections.stream().collect(Collectors.toMap(ClientConnection::name, Function.identity()));
        this.tokenValidators =
                tokenValidators.stream().collect(Collectors.toMap(TokenValidator::name, Function.identity()));
        this.userInfoProcessors = userInfoProcessors.stream()
                .collect(Collectors.toMap(UserInfoProcessor::connection, Function.identity()));
        this.idp = config.idp();
        this.connectionName = config.connectionName();
        this.validatorName = config.validatorName();
        this.path = config.path();
        this.cacheTtlSeconds = config.cacheTtlSeconds();
        this.cacheMaxSize = config.cacheMaxSize();
        this.fetchUserInfo = config.fetchUserInfo();

        // Initialize HTTP timeouts with validation
        int connectTimeout = config.httpConnectTimeoutMs();
        int readTimeout = config.httpReadTimeoutMs();
        this.httpConnectTimeoutMs = connectTimeout > 0 ? connectTimeout : DEFAULT_HTTP_CONNECT_TIMEOUT_MS;
        this.httpReadTimeoutMs = readTimeout > 0 ? readTimeout : DEFAULT_HTTP_READ_TIMEOUT_MS;

        // Validate that connectionName is configured
        if (connectionName == null || connectionName.isEmpty()) {
            throw new IllegalArgumentException("Connection name not configured");
        }

        // Validate that the specified connection exists
        if (!this.connections.containsKey(connectionName)) {
            throw new IllegalArgumentException("Configured connection '" + connectionName
                    + "' not found. Available connections: " + this.connections.keySet());
        }

        // Validate that validatorName is configured
        if (validatorName == null || validatorName.isEmpty()) {
            throw new IllegalArgumentException("Token validator name not configured");
        }

        // Validate that the specified validator exists
        if (!this.tokenValidators.containsKey(validatorName)) {
            throw new IllegalArgumentException("Configured token validator '" + validatorName
                    + "' not found. Available validators: " + this.tokenValidators.keySet());
        }

        // Log fetchUserInfo configuration
        if (fetchUserInfo) {
            logger.debug("User info fetching is enabled. Profile will be synchronized after token validation.");
        }

        // Log cache configuration
        if (cacheTtlSeconds <= 0) {
            logger.info("Token caching is disabled - cache TTL is 0 or negative");
        }

        logger.debug("activate: registering ExternalIdentityProvider");
        bundleContext.registerService(
                new String[] {ExternalIdentityProvider.class.getName(), CredentialsSupport.class.getName()},
                new OidcIdentityProvider(idp),
                null);

        logger.info(
                "OidcBearerAuthenticationHandler successfully activated with connection: {}, validator: {}, "
                        + "cache TTL: {}s, max size: {}, HTTP timeouts: connect={}ms, read={}ms",
                connectionName,
                validatorName,
                cacheTtlSeconds,
                cacheMaxSize,
                httpConnectTimeoutMs,
                httpReadTimeoutMs);
    }

    @Override
    @Nullable
    public AuthenticationInfo extractCredentials(
            @NotNull HttpServletRequest request, @NotNull HttpServletResponse response) {
        logger.debug("extractCredentials: checking for bearer token");

        // Extract the Authorization header
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith(BEARER_PREFIX)) {
            logger.debug("No bearer token found in Authorization header");
            return null;
        }

        String token = authHeader.substring(BEARER_PREFIX.length()).trim();
        if (token.isEmpty()) {
            logger.debug("Empty bearer token");
            return null;
        }

        try {
            // Check cache first (only if caching is enabled)
            if (cacheTtlSeconds > 0) {
                CachedToken cachedToken = tokenCache.get(token);
                if (cachedToken != null && !cachedToken.isExpired()) {
                    logger.debug("Using cached token for subject: {}", cachedToken.subject);
                    return createAuthenticationInfo(cachedToken.subject, cachedToken.claimsSet, token);
                }
            }

            // Get the configured connection
            ClientConnection connection = getConnection();
            if (connection == null) {
                logger.debug("Configured connection '{}' not found", connectionName);
                return null;
            }

            // Get the configured token validator
            TokenValidator validator = tokenValidators.get(validatorName);
            if (validator == null) {
                logger.debug("Configured token validator '{}' not found", validatorName);
                return null;
            }

            // Validate the token using the configured validator (includes claims validation)
            TokenValidator.TokenValidationResult tokenResult = validator.validate(token, connection);
            if (tokenResult == null) {
                logger.debug("Token validation failed");
                return null;
            }

            String subject = tokenResult.getSubject();
            JWTClaimsSet claimsSet = tokenResult.getClaimsSet();

            // Cache the validated token
            cacheToken(token, subject, claimsSet);

            logger.info("Bearer token validated successfully for subject: {}", subject);

            // Fetch user info if enabled
            String userInfoJson = null;
            if (fetchUserInfo) {
                userInfoJson = fetchUserInfoJson(token, connection);
            }

            return createAuthenticationInfoWithProcessor(
                    subject, connection, userInfoJson, claimsSet.getClaims(), token);

        } catch (Exception e) {
            logger.error("Error validating bearer token: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Fetches user information from the UserInfo endpoint and returns it as JSON string.
     *
     * @param token the bearer token to use for authentication
     * @param connection the OIDC connection
     * @return user info as JSON string, or {@code null} if fetch fails
     */
    @Nullable
    private String fetchUserInfoJson(@NotNull String token, @NotNull ClientConnection connection) {
        // Get userInfo URL from connection
        String userInfoUrl = null;
        if (connection instanceof OidcConnectionImpl) {
            OidcConnectionImpl oidcConn = (OidcConnectionImpl) connection;
            userInfoUrl = oidcConn.userInfoUrl();
        }

        if (userInfoUrl == null || userInfoUrl.isEmpty()) {
            logger.debug("No userInfo URL available for connection: {}", connection.name());
            return null;
        }

        logger.debug("Fetching user info from: {}", userInfoUrl);

        java.net.HttpURLConnection urlConnection = null;
        try {
            // Make HTTP request to UserInfo endpoint with configurable timeouts
            urlConnection = (java.net.HttpURLConnection) new URL(userInfoUrl).openConnection();
            urlConnection.setRequestMethod("GET");
            urlConnection.setRequestProperty("Authorization", "Bearer " + token);
            urlConnection.setRequestProperty("Accept", "application/json");
            urlConnection.setConnectTimeout(httpConnectTimeoutMs);
            urlConnection.setReadTimeout(httpReadTimeoutMs);

            int responseCode = urlConnection.getResponseCode();
            if (responseCode != 200) {
                logger.debug("UserInfo request failed with status: {}", responseCode);
                return null;
            }

            // Parse the UserInfo response using try-with-resources for the InputStream
            String responseBody;
            try (java.io.InputStream inputStream = urlConnection.getInputStream()) {
                responseBody = new String(inputStream.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
            }

            com.nimbusds.oauth2.sdk.http.HTTPResponse httpResponse = new HTTPResponse(responseCode);
            httpResponse.setContentType("application/json");
            httpResponse.setContent(responseBody);

            com.nimbusds.openid.connect.sdk.UserInfoResponse userInfoResponse =
                    com.nimbusds.openid.connect.sdk.UserInfoResponse.parse(httpResponse);

            if (!userInfoResponse.indicatesSuccess()) {
                logger.debug("UserInfo response indicates failure");
                return null;
            }

            com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse successResponse =
                    userInfoResponse.toSuccessResponse();
            com.nimbusds.openid.connect.sdk.claims.UserInfo userInfo = successResponse.getUserInfo();

            if (userInfo == null) {
                logger.debug("UserInfo response is empty");
                return null;
            }

            String userInfoJson = userInfo.toJSONObject().toJSONString();
            logger.debug("Successfully fetched user info for connection: {}", connection.name());
            return userInfoJson;

        } catch (Exception e) {
            logger.debug("Failed to fetch user info: {}", e.getMessage());
            return null;
        } finally {
            // Always disconnect the HttpURLConnection to release resources
            if (urlConnection != null) {
                urlConnection.disconnect();
            }
        }
    }

    /**
     * Creates an AuthenticationInfo object using the UserInfoProcessor.
     *
     * @param subject the subject from the token
     * @param connection the OIDC connection used for validation
     * @param userInfoJson the user info JSON (may be {@code null})
     * @param tokenClaims the token claims as a map
     * @param token the raw token string
     * @return AuthenticationInfo object
     */
    @NotNull
    private AuthenticationInfo createAuthenticationInfoWithProcessor(
            @NotNull String subject,
            @NotNull ClientConnection connection,
            @Nullable String userInfoJson,
            @NotNull Map<String, Object> tokenClaims,
            @NotNull String token) {

        // Get the UserInfoProcessor for this connection
        UserInfoProcessor processor = userInfoProcessors.get(connection.name());
        if (processor == null) {
            logger.warn(
                    "No UserInfoProcessor found for connection '{}'. Using fallback credentials creation.",
                    connection.name());
            // Fallback to manual creation if no processor is available
            return createAuthenticationInfoFallback(subject, tokenClaims, token);
        }

        // Create a token response JSON from the claims
        // The UserInfoProcessor expects a token response format
        net.minidev.json.JSONObject tokenResponseJson = new net.minidev.json.JSONObject();
        tokenResponseJson.put("access_token", token);
        tokenResponseJson.put("token_type", "Bearer");
        // Add token claims to the response
        for (Map.Entry<String, Object> entry : tokenClaims.entrySet()) {
            tokenResponseJson.put(entry.getKey(), entry.getValue());
        }

        String tokenResponseString = tokenResponseJson.toJSONString();

        // Process using the UserInfoProcessor
        OidcAuthCredentials credentials = processor.process(userInfoJson, tokenResponseString, subject, idp);

        // Create AuthenticationInfo
        AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, subject);
        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        return authInfo;
    }

    /**
     * Fallback method to create AuthenticationInfo when no UserInfoProcessor is available.
     *
     * @param subject the subject from the token
     * @param tokenClaims the token claims
     * @param token the raw token string
     * @return AuthenticationInfo object
     */
    @NotNull
    private AuthenticationInfo createAuthenticationInfoFallback(
            @NotNull String subject, @NotNull Map<String, Object> tokenClaims, @NotNull String token) {
        AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, subject);

        // Create credentials with claims
        OidcAuthCredentials credentials = new OidcAuthCredentials(subject, idp);
        credentials.setAttribute(".token", token);

        // Add all claims as attributes (converting Object values to String)
        for (Map.Entry<String, Object> entry : tokenClaims.entrySet()) {
            if (entry.getValue() != null) {
                credentials.setAttribute(entry.getKey(), entry.getValue().toString());
            }
        }

        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        return authInfo;
    }

    /**
     * Creates an AuthenticationInfo object from the validated token (used for cached tokens).
     *
     * @param subject the subject from the token
     * @param claimsSet the JWT claims set
     * @param token the raw token string
     * @return the AuthenticationInfo object
     */
    @NotNull
    private AuthenticationInfo createAuthenticationInfo(
            @NotNull String subject, @NotNull JWTClaimsSet claimsSet, @NotNull String token) {
        AuthenticationInfo authInfo = new AuthenticationInfo(AUTH_TYPE, subject);

        // Create credentials with claims
        OidcAuthCredentials credentials = new OidcAuthCredentials(subject, idp);
        credentials.setAttribute(".token", "");

        // Add all claims as attributes (converting Object values to String)
        for (Map.Entry<String, Object> entry : claimsSet.getClaims().entrySet()) {
            if (entry.getValue() != null) {
                credentials.setAttribute(entry.getKey(), entry.getValue().toString());
            }
        }

        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);
        return authInfo;
    }

    /**
     * Caches a validated token.
     *
     * @param token the token string
     * @param subject the subject from the token
     * @param claimsSet the JWT claims set
     */
    private void cacheToken(@NotNull String token, @NotNull String subject, @NotNull JWTClaimsSet claimsSet) {
        // Skip caching if disabled
        if (cacheTtlSeconds <= 0) {
            logger.debug("Token caching is disabled - not caching token for subject: {}", subject);
            return;
        }

        // Enforce cache size limit
        if (tokenCache.size() >= cacheMaxSize) {
            // Remove oldest entries (simple LRU-like behavior)
            long now = System.currentTimeMillis();
            tokenCache
                    .entrySet()
                    .removeIf(entry -> entry.getValue().isExpired()
                            || now - entry.getValue().cachedAt > TimeUnit.SECONDS.toMillis(cacheTtlSeconds));

            // If still over limit, remove oldest entries
            if (tokenCache.size() >= cacheMaxSize) {
                tokenCache.entrySet().stream()
                        .sorted((e1, e2) -> Long.compare(e1.getValue().cachedAt, e2.getValue().cachedAt))
                        .limit(tokenCache.size() - cacheMaxSize + 1)
                        .map(Map.Entry::getKey)
                        .collect(Collectors.toList())
                        .forEach(tokenCache::remove);
            }
        }

        tokenCache.put(token, new CachedToken(subject, claimsSet, cacheTtlSeconds));
        logger.debug("Cached token for subject: {} (cache size: {})", subject, tokenCache.size());
    }

    /**
     * Clears the token cache.
     */
    public void clearCache() {
        tokenCache.clear();
        logger.info("Token cache cleared");
    }

    /**
     * Gets the current cache size.
     *
     * @return the number of tokens in the cache
     */
    public int getCacheSize() {
        return tokenCache.size();
    }

    @Override
    public boolean requestCredentials(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response)
            throws IOException {
        logger.debug("requestCredentials: bearer authentication handler does not request credentials");
        // Bearer token authentication handler does not request credentials
        // Client must provide bearer token in Authorization header
        return false;
    }

    @Override
    public void dropCredentials(@Nullable HttpServletRequest request, @Nullable HttpServletResponse response) {
        // For bearer tokens, we don't need to do anything special on logout
        // The client should discard the token
        logger.debug("dropCredentials called");
    }

    /**
     * Internal class to represent a cached token with expiration.
     */
    private static class CachedToken {
        @NotNull
        final String subject;

        @NotNull
        final JWTClaimsSet claimsSet;

        final long cachedAt;
        final long ttlMillis;

        CachedToken(@NotNull String subject, @NotNull JWTClaimsSet claimsSet, long ttlSeconds) {
            this.subject = subject;
            this.claimsSet = claimsSet;
            this.cachedAt = System.currentTimeMillis();
            this.ttlMillis = TimeUnit.SECONDS.toMillis(ttlSeconds);
        }

        boolean isExpired() {
            return System.currentTimeMillis() - cachedAt > ttlMillis;
        }
    }
}
