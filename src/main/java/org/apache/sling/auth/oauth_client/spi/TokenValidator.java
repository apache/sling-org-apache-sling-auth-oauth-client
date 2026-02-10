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

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Service Provider Interface (SPI) for validating OAuth2/OIDC bearer tokens.
 *
 * <p>This interface defines the contract for token validation services that can be used
 * by authentication handlers to verify bearer tokens. Implementations can provide different
 * validation strategies such as:</p>
 *
 * <ul>
 *   <li><b>Offline validation</b> - Validates JWT tokens locally by verifying the signature
 *       using the issuer's public keys (JWK Set) and checking standard claims like issuer,
 *       expiration, and audience.</li>
 *   <li><b>Online validation</b> - Validates tokens by calling the OAuth2 token introspection
 *       endpoint of the authorization server to verify the token is active and retrieve its claims.</li>
 * </ul>
 *
 * <h2>Usage</h2>
 *
 * <p>Token validators are typically registered as OSGi services with a unique name. Authentication
 * handlers reference validators by name in their configuration. For example:</p>
 *
 * <pre>{@code
 * @Component(service = TokenValidator.class)
 * @Designate(ocd = MyTokenValidator.Config.class, factory = true)
 * public class MyTokenValidator implements TokenValidator {
 *
 *     @interface Config {
 *         String name();
 *     }
 *
 *     private final String name;
 *
 *     @Activate
 *     public MyTokenValidator(Config config) {
 *         this.name = config.name();
 *     }
 *
 *     @Override
 *     public String name() {
 *         return name;
 *     }
 *
 *     @Override
 *     public TokenValidationResult validate(String token, ClientConnection connection) {
 *         // Implement validation logic
 *         return new TokenValidationResult(subject, claimsSet);
 *     }
 * }
 * }</pre>
 *
 * <h2>Built-in Implementations</h2>
 *
 * <p>The following implementations are provided out of the box:</p>
 *
 * <ul>
 *   <li>{@code OfflineTokenValidator} - Validates JWT tokens using signature verification</li>
 *   <li>{@code OnlineTokenValidator} - Validates tokens using OAuth2 token introspection</li>
 * </ul>
 *
 * <p>Both implementations extend {@link AbstractTokenValidator} which provides common
 * claims validation logic for client ID, scopes, and audience.</p>
 *
 * @see AbstractTokenValidator
 * @see TokenValidationResult
 * @since 0.1.7
 */
public interface TokenValidator {

    /**
     * Returns the unique name of this token validator instance.
     *
     * <p>The name is used to identify this validator in configuration. Authentication handlers
     * reference validators by this name to specify which validator should be used for token
     * validation.</p>
     *
     * <p>Names should be unique across all registered token validators. It is recommended to use
     * descriptive names that indicate the validation strategy, such as "offline-validator" or
     * "introspection-validator".</p>
     *
     * @return the unique validator name, never {@code null}
     */
    @NotNull
    String name();

    /**
     * Validates the given bearer token.
     *
     * <p>This method performs token validation according to the implementation's strategy.
     * Implementations may:</p>
     *
     * <ul>
     *   <li>Parse and verify JWT signatures (offline validation)</li>
     *   <li>Call the token introspection endpoint (online validation)</li>
     *   <li>Validate standard claims (issuer, expiration, audience, etc.)</li>
     *   <li>Validate custom claims specific to the application</li>
     * </ul>
     *
     * <p>The connection parameter provides access to the OIDC provider's configuration,
     * including endpoints and credentials needed for validation.</p>
     *
     * @param token the bearer token to validate, must not be {@code null} or empty
     * @param connection the OIDC connection configuration to use for validation,
     *                   provides access to JWK Set URL, introspection endpoint, etc.
     * @return a {@link TokenValidationResult} containing the subject and claims if the token
     *         is valid, or {@code null} if validation fails for any reason (invalid signature,
     *         expired token, invalid claims, etc.)
     */
    @Nullable
    TokenValidationResult validate(@NotNull String token, @NotNull ClientConnection connection);

    /**
     * Represents the result of a successful token validation.
     *
     * <p>This class encapsulates the validated token's subject (the authenticated user identifier)
     * and the complete set of JWT claims extracted from the token or introspection response.</p>
     *
     * <p>The claims set can be used by authentication handlers to:</p>
     *
     * <ul>
     *   <li>Create authentication credentials with user attributes</li>
     *   <li>Perform additional authorization checks</li>
     *   <li>Extract user profile information</li>
     * </ul>
     *
     * <h2>Example Usage</h2>
     *
     * <pre>{@code
     * TokenValidationResult result = validator.validate(token, connection);
     * if (result != null) {
     *     String userId = result.getSubject();
     *     JWTClaimsSet claims = result.getClaimsSet();
     *
     *     // Extract additional claims
     *     String email = claims.getStringClaim("email");
     *     List<String> groups = claims.getStringListClaim("groups");
     * }
     * }</pre>
     *
     * @see TokenValidator#validate(String, ClientConnection)
     * @since 0.1.7
     */
    class TokenValidationResult {

        private final String subject;
        private final JWTClaimsSet claimsSet;

        /**
         * Creates a new token validation result.
         *
         * @param subject the subject (user identifier) from the validated token,
         *                typically the "sub" claim, must not be {@code null}
         * @param claimsSet the complete set of JWT claims from the token or
         *                  introspection response, must not be {@code null}
         */
        public TokenValidationResult(@NotNull String subject, @NotNull JWTClaimsSet claimsSet) {
            this.subject = subject;
            this.claimsSet = claimsSet;
        }

        /**
         * Returns the subject (user identifier) from the validated token.
         *
         * <p>The subject is typically the "sub" claim from the JWT token or introspection
         * response. This value uniquely identifies the authenticated user and is used
         * as the user ID for authentication.</p>
         *
         * @return the subject identifier, never {@code null}
         */
        @NotNull
        public String getSubject() {
            return subject;
        }

        /**
         * Returns the complete set of JWT claims from the validated token.
         *
         * <p>The claims set contains all claims from the token (for offline validation)
         * or from the introspection response (for online validation). Common claims include:</p>
         *
         * <ul>
         *   <li>{@code sub} - Subject (user identifier)</li>
         *   <li>{@code iss} - Issuer</li>
         *   <li>{@code aud} - Audience</li>
         *   <li>{@code exp} - Expiration time</li>
         *   <li>{@code iat} - Issued at time</li>
         *   <li>{@code scope} - OAuth2 scopes</li>
         *   <li>{@code client_id} - Client identifier</li>
         *   <li>{@code email} - User email (if available)</li>
         *   <li>{@code name} - User name (if available)</li>
         * </ul>
         *
         * @return the JWT claims set, never {@code null}
         */
        @NotNull
        public JWTClaimsSet getClaimsSet() {
            return claimsSet;
        }
    }
}
