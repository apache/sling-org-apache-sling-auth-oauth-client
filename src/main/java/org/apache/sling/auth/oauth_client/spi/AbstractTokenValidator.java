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
package org.apache.sling.auth.oauth_client.spi;

import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

import com.nimbusds.jwt.JWTClaimsSet;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base class for {@link TokenValidator} implementations that provides common
 * claims validation logic.
 *
 * <p>This class implements the Template Method pattern, where the {@link #validate(String,
 * org.apache.sling.auth.oauth_client.ClientConnection)} method defines the overall validation
 * algorithm:</p>
 *
 * <ol>
 *   <li>Perform implementation-specific validation via {@link #doValidate(String,
 *       org.apache.sling.auth.oauth_client.ClientConnection)}</li>
 *   <li>Validate client ID against configured accepted values</li>
 *   <li>Validate scopes against configured required values</li>
 *   <li>Validate audience against configured required values</li>
 * </ol>
 *
 * <p>Subclasses must implement the {@link #doValidate(String,
 * org.apache.sling.auth.oauth_client.ClientConnection)} method to perform the actual token
 * validation (e.g., JWT signature verification or token introspection).</p>
 *
 * <h2>Claims Validation</h2>
 *
 * <p>The following claims validations are supported and are all optional (disabled when
 * the corresponding configuration is null or empty):</p>
 *
 * <ul>
 *   <li><b>Client ID</b> - Validates that the token's {@code client_id} or {@code azp} claim
 *       matches one of the configured accepted client IDs</li>
 *   <li><b>Scopes</b> - Validates that the token has ALL of the configured required scopes
 *       (from the {@code scope} or {@code scp} claim)</li>
 *   <li><b>Audience</b> - Validates that the token's {@code aud} claim contains at least one
 *       of the configured required audiences</li>
 * </ul>
 *
 * <h2>Example Implementation</h2>
 *
 * <pre>{@code
 * @Component(service = TokenValidator.class)
 * @Designate(ocd = MyTokenValidator.Config.class, factory = true)
 * public class MyTokenValidator extends AbstractTokenValidator {
 *
 *     @interface Config {
 *         String name();
 *         String[] acceptedClientIds() default {};
 *         String[] requiredScopes() default {};
 *         String[] requiredAudiences() default {};
 *     }
 *
 *     @Activate
 *     public MyTokenValidator(Config config) {
 *         super(config.name(), config.acceptedClientIds(),
 *               config.requiredScopes(), config.requiredAudiences());
 *
 *         validateName(config.name());
 *         validateConfigArray(config.acceptedClientIds(), "Accepted client IDs");
 *         validateConfigArray(config.requiredScopes(), "Required scopes");
 *         validateConfigArray(config.requiredAudiences(), "Required audiences");
 *     }
 *
 *     @Override
 *     protected TokenValidationResult doValidate(String token, ClientConnection connection) {
 *         // Implement token-specific validation (signature, introspection, etc.)
 *         // Return TokenValidationResult on success, null on failure
 *     }
 * }
 * }</pre>
 *
 * @see TokenValidator
 * @see TokenValidator.TokenValidationResult
 * @since 0.1.7
 */
public abstract class AbstractTokenValidator implements TokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(AbstractTokenValidator.class);

    private final String name;
    private final String[] acceptedClientIds;
    private final String[] requiredScopes;
    private final String[] requiredAudiences;

    /**
     * Constructs a new abstract token validator with the given configuration.
     *
     * <p>This constructor initializes the validator with optional claims validation
     * configuration. Each validation type can be disabled by passing {@code null} or
     * an empty array.</p>
     *
     * <p>Configuration logging is performed at construction time:</p>
     * <ul>
     *   <li>DEBUG level: logs configured values when validation is enabled</li>
     *   <li>INFO level: logs when a validation type is disabled</li>
     * </ul>
     *
     * @param name the unique name of this validator instance, used for identification
     *             in configuration and logging
     * @param acceptedClientIds list of accepted OAuth2 client IDs; if {@code null} or empty,
     *                          client ID validation is skipped
     * @param requiredScopes list of required OAuth2 scopes; if {@code null} or empty,
     *                       scope validation is skipped; tokens must have ALL specified scopes
     * @param requiredAudiences list of required audiences; if {@code null} or empty,
     *                          audience validation is skipped; tokens must have at least ONE
     *                          specified audience
     */
    protected AbstractTokenValidator(
            @NotNull String name,
            @Nullable String[] acceptedClientIds,
            @Nullable String[] requiredScopes,
            @Nullable String[] requiredAudiences) {
        this.name = name;
        this.acceptedClientIds = acceptedClientIds;
        this.requiredScopes = requiredScopes;
        this.requiredAudiences = requiredAudiences;

        // Log configuration
        if (acceptedClientIds != null && acceptedClientIds.length > 0) {
            logger.debug("Validator '{}' - Accepted client IDs: {}", name, String.join(", ", acceptedClientIds));
        } else {
            logger.info("Validator '{}' - Client ID validation is disabled", name);
        }

        if (requiredScopes != null && requiredScopes.length > 0) {
            logger.debug("Validator '{}' - Required scopes: {}", name, String.join(", ", requiredScopes));
        } else {
            logger.info("Validator '{}' - Scope validation is disabled", name);
        }

        if (requiredAudiences != null && requiredAudiences.length > 0) {
            logger.debug("Validator '{}' - Required audiences: {}", name, String.join(", ", requiredAudiences));
        } else {
            logger.info("Validator '{}' - Audience validation is disabled", name);
        }
    }

    /**
     * {@inheritDoc}
     *
     * @return the validator name configured at construction time
     */
    @Override
    @NotNull
    public final String name() {
        return name;
    }

    /**
     * Validates the given bearer token using a two-phase validation process.
     *
     * <p>This method implements the Template Method pattern:</p>
     *
     * <ol>
     *   <li><b>Phase 1: Implementation-specific validation</b> - Calls {@link #doValidate(String,
     *       org.apache.sling.auth.oauth_client.ClientConnection)} to perform token-specific
     *       validation (e.g., signature verification or introspection)</li>
     *   <li><b>Phase 2: Claims validation</b> - If Phase 1 succeeds, validates the token's
     *       claims against the configured requirements:
     *       <ul>
     *         <li>Client ID validation (if configured)</li>
     *         <li>Scope validation (if configured)</li>
     *         <li>Audience validation (if configured)</li>
     *       </ul>
     *   </li>
     * </ol>
     *
     * <p>Validation fails (returns {@code null}) if any phase or validation step fails.</p>
     *
     * @param token the bearer token to validate
     * @param connection the OIDC connection to use for validation
     * @return a {@link TokenValidationResult} if all validations pass, {@code null} otherwise
     */
    @Override
    @Nullable
    public final TokenValidationResult validate(
            @NotNull String token, @NotNull org.apache.sling.auth.oauth_client.ClientConnection connection) {
        // First, perform the implementation-specific validation (signature or introspection)
        TokenValidationResult result = doValidate(token, connection);
        if (result == null) {
            return null;
        }

        // Then validate claims
        JWTClaimsSet claimsSet = result.getClaimsSet();

        // Validate client ID
        if (!validateClientId(claimsSet)) {
            return null;
        }

        // Validate scopes
        if (!validateScopes(claimsSet)) {
            return null;
        }

        // Validate audience
        if (!validateAudience(claimsSet)) {
            return null;
        }

        return result;
    }

    /**
     * Performs the implementation-specific token validation.
     *
     * <p>Subclasses must implement this method to perform the actual token validation
     * appropriate for their validation strategy. Common implementations include:</p>
     *
     * <ul>
     *   <li><b>Offline validation</b>: Parse the JWT, verify the signature using the
     *       issuer's JWK Set, and validate standard claims (issuer, expiration)</li>
     *   <li><b>Online validation</b>: Call the OAuth2 token introspection endpoint
     *       to verify the token is active and retrieve its claims</li>
     * </ul>
     *
     * <p>This method is called as the first step in the validation process, before
     * claims validation. If this method returns {@code null}, no further validation
     * is performed.</p>
     *
     * @param token the bearer token to validate
     * @param connection the OIDC connection providing configuration such as JWK Set URL,
     *                   introspection endpoint, client credentials, and issuer
     * @return a {@link TokenValidationResult} containing the subject and claims if the
     *         token is valid (before claims validation), or {@code null} if validation fails
     */
    @Nullable
    protected abstract TokenValidationResult doValidate(
            @NotNull String token, @NotNull org.apache.sling.auth.oauth_client.ClientConnection connection);

    /**
     * Validates that the token's client ID is in the list of accepted client IDs.
     *
     * <p>This method checks the token's {@code client_id} claim first, falling back to
     * the {@code azp} (authorized party) claim if {@code client_id} is not present.
     * The {@code azp} claim is commonly used by identity providers like Keycloak.</p>
     *
     * <p>Validation is skipped (returns {@code true}) if no accepted client IDs are
     * configured.</p>
     *
     * @param claimsSet the JWT claims set containing the token's claims
     * @return {@code true} if client ID validation passes or is not configured,
     *         {@code false} if the token's client ID is not in the accepted list
     *         or the token has no client ID claim
     */
    protected boolean validateClientId(@NotNull JWTClaimsSet claimsSet) {
        if (acceptedClientIds == null || acceptedClientIds.length == 0) {
            logger.debug("No accepted client IDs configured - skipping client ID validation");
            return true;
        }

        // Get client_id claim from the token (try both client_id and azp)
        String clientId = null;
        try {
            clientId = claimsSet.getStringClaim("client_id");
            if (clientId == null || clientId.isEmpty()) {
                // Try azp (authorized party) as fallback - commonly used in Keycloak
                clientId = claimsSet.getStringClaim("azp");
            }
        } catch (ParseException e) {
            logger.debug("Failed to parse client_id from token: {}", e.getMessage());
        }

        if (clientId == null || clientId.isEmpty()) {
            logger.debug("Token does not contain a client_id or azp claim");
            return false;
        }

        // Check if client_id is in the accepted list
        for (String acceptedClientId : acceptedClientIds) {
            if (clientId.equals(acceptedClientId)) {
                logger.debug("Token client_id '{}' is accepted", clientId);
                return true;
            }
        }

        logger.debug(
                "Token client_id '{}' is not in the list of accepted client IDs: {}",
                clientId,
                String.join(", ", acceptedClientIds));
        return false;
    }

    /**
     * Validates that the token has ALL of the required scopes.
     *
     * <p>This method checks the token's {@code scope} claim first, falling back to
     * the {@code scp} claim if {@code scope} is not present. Scopes are expected to
     * be space-separated as per OAuth2 specification.</p>
     *
     * <p>Unlike audience validation (which requires at least one match), scope validation
     * requires the token to have ALL configured required scopes.</p>
     *
     * <p>Validation is skipped (returns {@code true}) if no required scopes are configured.</p>
     *
     * @param claimsSet the JWT claims set containing the token's claims
     * @return {@code true} if scope validation passes or is not configured,
     *         {@code false} if the token is missing any required scope or has no scope claim
     */
    protected boolean validateScopes(@NotNull JWTClaimsSet claimsSet) {
        if (requiredScopes == null || requiredScopes.length == 0) {
            logger.debug("No required scopes configured - skipping scope validation");
            return true;
        }

        // Try to get scopes from the token
        String scopeString = null;
        try {
            scopeString = claimsSet.getStringClaim("scope");
            if (scopeString == null) {
                scopeString = claimsSet.getStringClaim("scp");
            }
        } catch (ParseException e) {
            logger.debug("Failed to parse scope from token: {}", e.getMessage());
        }

        if (scopeString == null || scopeString.isEmpty()) {
            logger.debug("Token does not contain a scope claim");
            return false;
        }

        // Split scopes (usually space-separated)
        List<String> tokenScopesList = Arrays.asList(scopeString.split("\\s+"));

        // Check if token has ALL required scopes
        for (String requiredScope : requiredScopes) {
            if (!tokenScopesList.contains(requiredScope)) {
                logger.debug(
                        "Token is missing required scope '{}'. Token scopes: {}, Required scopes: {}",
                        requiredScope,
                        scopeString,
                        String.join(", ", requiredScopes));
                return false;
            }
        }

        logger.debug("Token has all required scopes: {}", String.join(", ", requiredScopes));
        return true;
    }

    /**
     * Validates that the token's audience matches at least one of the required audiences.
     *
     * <p>This method checks the token's {@code aud} claim, which may contain a single
     * audience or multiple audiences as per JWT specification.</p>
     *
     * <p>Unlike scope validation (which requires all scopes), audience validation
     * passes if the token has at least ONE of the configured required audiences.</p>
     *
     * <p>Validation is skipped (returns {@code true}) if no required audiences are
     * configured.</p>
     *
     * @param claimsSet the JWT claims set containing the token's claims
     * @return {@code true} if audience validation passes or is not configured,
     *         {@code false} if the token has none of the required audiences or has
     *         no audience claim
     */
    protected boolean validateAudience(@NotNull JWTClaimsSet claimsSet) {
        if (requiredAudiences == null || requiredAudiences.length == 0) {
            logger.debug("No required audiences configured - skipping audience validation");
            return true;
        }

        List<String> tokenAudiences = claimsSet.getAudience();
        if (tokenAudiences == null || tokenAudiences.isEmpty()) {
            logger.debug("Token does not contain an audience claim");
            return false;
        }

        // Check if token has at least one of the required audiences
        for (String tokenAudience : tokenAudiences) {
            for (String requiredAudience : requiredAudiences) {
                if (tokenAudience.equals(requiredAudience)) {
                    logger.debug("Token has required audience: {}", tokenAudience);
                    return true;
                }
            }
        }

        logger.debug("Token does not have any of the required audiences: {}", Arrays.toString(requiredAudiences));
        return false;
    }

    /**
     * Returns the configured accepted client IDs.
     *
     * <p>This method is provided for subclasses that may need to access the configuration
     * for custom validation logic or logging.</p>
     *
     * @return the accepted client IDs array, or {@code null} if not configured
     */
    @Nullable
    protected String[] getAcceptedClientIds() {
        return acceptedClientIds;
    }

    /**
     * Returns the configured required scopes.
     *
     * <p>This method is provided for subclasses that may need to access the configuration
     * for custom validation logic or logging.</p>
     *
     * @return the required scopes array, or {@code null} if not configured
     */
    @Nullable
    protected String[] getRequiredScopes() {
        return requiredScopes;
    }

    /**
     * Returns the configured required audiences.
     *
     * <p>This method is provided for subclasses that may need to access the configuration
     * for custom validation logic or logging.</p>
     *
     * @return the required audiences array, or {@code null} if not configured
     */
    @Nullable
    protected String[] getRequiredAudiences() {
        return requiredAudiences;
    }

    /**
     * Validates that a configuration array does not contain empty or null values.
     *
     * <p>This utility method should be called during component activation to validate
     * configuration arrays. It ensures that all configured values are meaningful
     * (non-null and non-empty after trimming whitespace).</p>
     *
     * <p>Example usage in a subclass:</p>
     *
     * <pre>{@code
     * @Activate
     * public MyTokenValidator(Config config) {
     *     super(config.name(), config.acceptedClientIds(),
     *           config.requiredScopes(), config.requiredAudiences());
     *
     *     validateConfigArray(config.acceptedClientIds(), "Accepted client IDs");
     *     validateConfigArray(config.requiredScopes(), "Required scopes");
     *     validateConfigArray(config.requiredAudiences(), "Required audiences");
     * }
     * }</pre>
     *
     * @param values the array to validate; {@code null} arrays are allowed and pass validation
     * @param configName the name of the configuration property for error messages
     * @throws IllegalArgumentException if the array contains any {@code null} or empty
     *                                  (after trimming) values
     */
    protected static void validateConfigArray(@Nullable String[] values, @NotNull String configName) {
        if (values != null) {
            for (String value : values) {
                if (value == null || value.trim().isEmpty()) {
                    throw new IllegalArgumentException(configName
                            + " configuration contains empty or null values. All entries must be non-empty strings.");
                }
            }
        }
    }

    /**
     * Validates that the validator name is properly configured.
     *
     * <p>This utility method should be called during component activation to ensure
     * the validator has a valid name. The name is required for identifying the validator
     * in configuration and logging.</p>
     *
     * <p>Example usage in a subclass:</p>
     *
     * <pre>{@code
     * @Activate
     * public MyTokenValidator(Config config) {
     *     super(config.name(), config.acceptedClientIds(),
     *           config.requiredScopes(), config.requiredAudiences());
     *
     *     validateName(config.name());
     * }
     * }</pre>
     *
     * @param name the validator name to validate
     * @throws IllegalArgumentException if the name is {@code null} or empty
     */
    protected static void validateName(@Nullable String name) {
        if (name == null || name.isEmpty()) {
            throw new IllegalArgumentException("Validator name must be configured");
        }
    }
}
