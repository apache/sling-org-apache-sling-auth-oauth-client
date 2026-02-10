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

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.auth.oauth_client.spi.AbstractTokenValidator;
import org.apache.sling.auth.oauth_client.spi.TokenValidator;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Offline token validator that validates JWT tokens using signature verification.
 *
 * <p>This validator parses the JWT, verifies the signature using the JWK Set from the OIDC provider,
 * and validates the issuer, expiration, and not-before claims.</p>
 *
 * <h2>Security Features</h2>
 * <ul>
 *   <li><b>Algorithm validation</b>: Only allows configured secure algorithms (RS256, RS384, RS512,
 *       ES256, ES384, ES512 by default). The "none" algorithm is always rejected.</li>
 *   <li><b>JWK Set caching</b>: Caches the JWK Set to prevent DoS attacks and improve performance.</li>
 *   <li><b>Clock skew tolerance</b>: Configurable tolerance for time-based claim validation.</li>
 *   <li><b>Not-before (nbf) validation</b>: Validates the nbf claim if present.</li>
 * </ul>
 *
 * @see AbstractTokenValidator
 * @see TokenValidator
 * @since 0.1.7
 */
@Component(service = TokenValidator.class)
@Designate(ocd = OfflineTokenValidator.Config.class, factory = true)
public class OfflineTokenValidator extends AbstractTokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(OfflineTokenValidator.class);

    /**
     * Default allowed algorithms for JWT signature verification.
     * Only RSA and EC algorithms are allowed by default. The "none" algorithm is never allowed.
     */
    private static final String[] DEFAULT_ALLOWED_ALGORITHMS = {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"};

    /**
     * Default clock skew tolerance in seconds.
     */
    private static final long DEFAULT_CLOCK_SKEW_SECONDS = 60;

    /**
     * Default JWK Set cache TTL in seconds (5 minutes).
     */
    private static final long DEFAULT_JWK_CACHE_TTL_SECONDS = 300;

    private final Set<String> allowedAlgorithms;
    private final long clockSkewMillis;
    private final long jwkCacheTtlMillis;

    /**
     * Cache for JWK Sets, keyed by JWK Set URL.
     */
    private final ConcurrentHashMap<URI, CachedJWKSet> jwkSetCache = new ConcurrentHashMap<>();

    @ObjectClassDefinition(
            name = "Apache Sling OIDC Offline Token Validator",
            description = "Token validator that performs offline JWT signature verification")
    @interface Config {
        @AttributeDefinition(
                name = "Validator Name",
                description =
                        "Unique name for this token validator instance. Used to reference this validator from authentication handlers.")
        @NotNull
        String name();

        @AttributeDefinition(
                name = "Accepted Client IDs",
                description =
                        "List of accepted OAuth2 client IDs. Only tokens issued to one of these client IDs will be accepted. If not configured or empty, client ID validation is skipped.",
                cardinality = Integer.MAX_VALUE)
        @Nullable
        String[] acceptedClientIds() default {};

        @AttributeDefinition(
                name = "Required Scopes",
                description =
                        "List of required OAuth2 scopes. Tokens must have ALL of these scopes to be accepted. If not configured or empty, scope validation is skipped.",
                cardinality = Integer.MAX_VALUE)
        @Nullable
        String[] requiredScopes() default {};

        @AttributeDefinition(
                name = "Required Audiences",
                description =
                        "List of required audiences. Tokens must have at least one of these audiences to be accepted. If not configured or empty, audience validation is skipped.",
                cardinality = Integer.MAX_VALUE)
        @Nullable
        String[] requiredAudiences() default {};

        @AttributeDefinition(
                name = "Allowed Algorithms",
                description =
                        "List of allowed JWT signature algorithms. Only tokens signed with one of these algorithms will be accepted. "
                                + "Default: RS256, RS384, RS512, ES256, ES384, ES512. The 'none' algorithm is never allowed for security reasons.",
                cardinality = Integer.MAX_VALUE)
        @NotNull
        String[] allowedAlgorithms() default {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"};

        @AttributeDefinition(
                name = "Clock Skew (seconds)",
                description = "Tolerance in seconds for clock skew when validating time-based claims (exp, nbf). "
                        + "This accounts for minor time differences between servers. Default: 60 seconds.")
        long clockSkewSeconds() default 60;

        @AttributeDefinition(
                name = "JWK Set Cache TTL (seconds)",
                description =
                        "Time to live for cached JWK Sets in seconds. The JWK Set is fetched from the OIDC provider "
                                + "and cached to improve performance and prevent DoS attacks. Default: 300 seconds (5 minutes). "
                                + "Set to 0 to disable caching (not recommended for production).")
        long jwkCacheTtlSeconds() default 300;
    }

    /**
     * Activates the offline token validator with the given configuration.
     *
     * @param config the OSGi configuration
     * @throws IllegalArgumentException if the configuration is invalid
     */
    @Activate
    public OfflineTokenValidator(@NotNull Config config) {
        super(config.name(), config.acceptedClientIds(), config.requiredScopes(), config.requiredAudiences());

        validateName(config.name());
        validateConfigArray(config.acceptedClientIds(), "Accepted client IDs");
        validateConfigArray(config.requiredScopes(), "Required scopes");
        validateConfigArray(config.requiredAudiences(), "Required audiences");

        // Initialize allowed algorithms
        String[] algorithms = config.allowedAlgorithms();
        if (algorithms == null || algorithms.length == 0) {
            algorithms = DEFAULT_ALLOWED_ALGORITHMS;
        }
        this.allowedAlgorithms = new HashSet<>(Arrays.asList(algorithms));

        // Validate that "none" is not in allowed algorithms (security check)
        if (this.allowedAlgorithms.contains("none") || this.allowedAlgorithms.contains("NONE")) {
            throw new IllegalArgumentException(
                    "The 'none' algorithm is not allowed for security reasons. Remove it from allowedAlgorithms.");
        }

        // Initialize clock skew
        long clockSkewSeconds = config.clockSkewSeconds();
        if (clockSkewSeconds < 0) {
            clockSkewSeconds = DEFAULT_CLOCK_SKEW_SECONDS;
        }
        this.clockSkewMillis = TimeUnit.SECONDS.toMillis(clockSkewSeconds);

        // Initialize JWK cache TTL
        long jwkCacheTtl = config.jwkCacheTtlSeconds();
        if (jwkCacheTtl < 0) {
            jwkCacheTtl = DEFAULT_JWK_CACHE_TTL_SECONDS;
        }
        this.jwkCacheTtlMillis = TimeUnit.SECONDS.toMillis(jwkCacheTtl);

        if (jwkCacheTtlMillis == 0) {
            logger.warn("JWK Set caching is disabled. This is not recommended for production as it may cause "
                    + "performance issues and make the system vulnerable to DoS attacks.");
        }

        logger.info(
                "OfflineTokenValidator '{}' activated with algorithms: {}, clock skew: {}s, JWK cache TTL: {}s",
                config.name(),
                String.join(", ", this.allowedAlgorithms),
                clockSkewSeconds,
                jwkCacheTtl);
    }

    @Override
    @Nullable
    protected TokenValidationResult doValidate(@NotNull String token, @NotNull ClientConnection connection) {
        try {
            // Parse and validate the token
            JWT jwt = JWTParser.parse(token);
            if (!(jwt instanceof SignedJWT)) {
                logger.debug("Token is not a signed JWT");
                return null;
            }

            SignedJWT signedJWT = (SignedJWT) jwt;

            // Validate algorithm before any other processing (security: prevent algorithm confusion)
            JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
            if (!isAlgorithmAllowed(algorithm)) {
                logger.debug(
                        "JWT algorithm '{}' is not in the list of allowed algorithms: {}",
                        algorithm.getName(),
                        String.join(", ", allowedAlgorithms));
                return null;
            }

            JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

            // Resolve the OIDC connection
            ResolvedConnection resolved = ResolvedOidcConnection.resolve(connection);
            if (!(resolved instanceof ResolvedOidcConnection)) {
                logger.debug("Connection is not an OIDC connection");
                return null;
            }

            ResolvedOidcConnection oidcConnection = (ResolvedOidcConnection) resolved;

            // Validate the token signature, issuer, expiration, and not-before
            if (!validateTokenSignature(signedJWT, oidcConnection, claimsSet)) {
                return null;
            }

            // Extract subject
            String subject = claimsSet.getSubject();
            if (subject == null || subject.isEmpty()) {
                logger.debug("Token has no subject claim");
                return null;
            }

            logger.debug("Token validated successfully (offline) for subject: {}", subject);
            return new TokenValidationResult(subject, claimsSet);

        } catch (ParseException e) {
            logger.debug("Failed to parse token: {}", e.getMessage());
            return null;
        } catch (Exception e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Checks if the given algorithm is in the allowed list.
     *
     * @param algorithm the JWT algorithm to check
     * @return {@code true} if the algorithm is allowed, {@code false} otherwise
     */
    private boolean isAlgorithmAllowed(@NotNull JWSAlgorithm algorithm) {
        return allowedAlgorithms.contains(algorithm.getName());
    }

    /**
     * Validates the token signature, issuer, expiration, and not-before claims.
     *
     * @param signedJWT the signed JWT to validate
     * @param connection the resolved OIDC connection
     * @param claimsSet the JWT claims set
     * @return {@code true} if validation passes, {@code false} otherwise
     */
    private boolean validateTokenSignature(
            @NotNull SignedJWT signedJWT, @NotNull ResolvedOidcConnection connection, @NotNull JWTClaimsSet claimsSet) {
        try {
            // Validate issuer
            String issuerClaim = claimsSet.getIssuer();
            if (!connection.issuer().equals(issuerClaim)) {
                logger.debug("Issuer mismatch: expected {}, got {}", connection.issuer(), issuerClaim);
                return false;
            }

            // Get current time for time-based validations
            long nowMillis = System.currentTimeMillis();
            Date now = new Date(nowMillis);
            Date nowPlusSkew = new Date(nowMillis + clockSkewMillis);
            Date nowMinusSkew = new Date(nowMillis - clockSkewMillis);

            // Validate expiration (with clock skew tolerance)
            Date expirationTime = claimsSet.getExpirationTime();
            if (expirationTime != null && expirationTime.before(nowMinusSkew)) {
                logger.debug("Token has expired at {} (current time with skew: {})", expirationTime, nowMinusSkew);
                return false;
            }

            // Validate not-before (with clock skew tolerance) - Fix #3
            Date notBeforeTime = claimsSet.getNotBeforeTime();
            if (notBeforeTime != null && notBeforeTime.after(nowPlusSkew)) {
                logger.debug("Token is not yet valid. nbf: {}, current time with skew: {}", notBeforeTime, nowPlusSkew);
                return false;
            }

            // Get JWK Set (with caching) - Fix #5
            JWKSet jwkSet = getJWKSet(connection.jwkSetURL());
            if (jwkSet == null) {
                logger.debug("Failed to retrieve JWK Set");
                return false;
            }

            // Get the key ID from the JWT header
            String keyID = signedJWT.getHeader().getKeyID();
            if (keyID == null) {
                logger.debug("No key ID in JWT header");
                return false;
            }

            // Find the matching key in the JWK set
            JWK jwk = jwkSet.getKeyByKeyId(keyID);
            if (jwk == null) {
                logger.debug("No matching key found for key ID: {}", keyID);
                return false;
            }

            // Create appropriate verifier based on key type - Fix #4
            JWSVerifier verifier = createVerifier(jwk, signedJWT.getHeader().getAlgorithm());
            if (verifier == null) {
                logger.debug("Could not create verifier for key type: {}", jwk.getKeyType());
                return false;
            }

            // Verify the signature
            if (!signedJWT.verify(verifier)) {
                logger.debug("Signature verification failed");
                return false;
            }

            return true;
        } catch (JOSEException | IOException | ParseException e) {
            logger.debug("Token validation failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Creates a JWS verifier for the given JWK and algorithm.
     *
     * @param jwk the JSON Web Key
     * @param algorithm the JWS algorithm
     * @return a JWS verifier, or {@code null} if the key type is not supported
     * @throws JOSEException if verifier creation fails
     */
    @Nullable
    private JWSVerifier createVerifier(@NotNull JWK jwk, @NotNull JWSAlgorithm algorithm) throws JOSEException {
        if (jwk instanceof RSAKey) {
            return new RSASSAVerifier((RSAKey) jwk);
        } else if (jwk instanceof ECKey) {
            return new ECDSAVerifier((ECKey) jwk);
        } else {
            logger.debug("Unsupported key type: {}. Only RSA and EC keys are supported.", jwk.getKeyType());
            return null;
        }
    }

    /**
     * Gets the JWK Set from the cache or fetches it from the URL.
     *
     * @param jwkSetURL the JWK Set URL
     * @return the JWK Set, or {@code null} if it could not be retrieved
     * @throws IOException if the JWK Set could not be loaded
     * @throws ParseException if the JWK Set could not be parsed
     */
    @Nullable
    private JWKSet getJWKSet(@NotNull URI jwkSetURL) throws IOException, ParseException {
        // If caching is disabled, fetch directly
        if (jwkCacheTtlMillis == 0) {
            return JWKSet.load(jwkSetURL.toURL());
        }

        // Check cache
        CachedJWKSet cached = jwkSetCache.get(jwkSetURL);
        if (cached != null && !cached.isExpired()) {
            logger.debug("Using cached JWK Set for: {}", jwkSetURL);
            return cached.jwkSet;
        }

        // Fetch and cache
        logger.debug("Fetching JWK Set from: {}", jwkSetURL);
        JWKSet jwkSet = JWKSet.load(jwkSetURL.toURL());
        jwkSetCache.put(jwkSetURL, new CachedJWKSet(jwkSet, jwkCacheTtlMillis));

        // Clean up expired entries
        jwkSetCache.entrySet().removeIf(entry -> entry.getValue().isExpired());

        return jwkSet;
    }

    /**
     * Clears the JWK Set cache. Useful for testing or when keys are rotated.
     */
    public void clearJWKSetCache() {
        jwkSetCache.clear();
        logger.info("JWK Set cache cleared");
    }

    /**
     * Internal class to represent a cached JWK Set with expiration.
     */
    private static class CachedJWKSet {
        @NotNull
        final JWKSet jwkSet;

        final long cachedAt;
        final long ttlMillis;

        CachedJWKSet(@NotNull JWKSet jwkSet, long ttlMillis) {
            this.jwkSet = jwkSet;
            this.cachedAt = System.currentTimeMillis();
            this.ttlMillis = ttlMillis;
        }

        boolean isExpired() {
            return System.currentTimeMillis() - cachedAt > ttlMillis;
        }
    }
}
