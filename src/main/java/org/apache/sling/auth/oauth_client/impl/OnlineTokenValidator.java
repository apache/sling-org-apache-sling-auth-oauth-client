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
import java.util.stream.Collectors;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.minidev.json.JSONObject;
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
 * Online token validator that validates tokens using OAuth2 token introspection.
 *
 * <p>This validator calls the introspection endpoint of the OIDC provider to verify
 * that the token is active and retrieve its claims. This approach is more secure than
 * offline validation as it can detect revoked tokens, but it requires a network call
 * for each validation.</p>
 *
 * <h2>When to Use</h2>
 * <ul>
 *   <li>When token revocation must be detected immediately</li>
 *   <li>When opaque (non-JWT) tokens are used</li>
 *   <li>When the authorization server supports introspection</li>
 * </ul>
 *
 * @see AbstractTokenValidator
 * @see TokenValidator
 * @since 0.1.7
 */
@Component(service = TokenValidator.class)
@Designate(ocd = OnlineTokenValidator.Config.class, factory = true)
public class OnlineTokenValidator extends AbstractTokenValidator {

    private static final Logger logger = LoggerFactory.getLogger(OnlineTokenValidator.class);

    @ObjectClassDefinition(
            name = "Apache Sling OIDC Online Token Validator",
            description = "Token validator that performs online token introspection")
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
    }

    /**
     * Activates the online token validator with the given configuration.
     *
     * @param config the OSGi configuration
     * @throws IllegalArgumentException if the configuration is invalid
     */
    @Activate
    public OnlineTokenValidator(@NotNull Config config) {
        super(config.name(), config.acceptedClientIds(), config.requiredScopes(), config.requiredAudiences());

        validateName(config.name());
        validateConfigArray(config.acceptedClientIds(), "Accepted client IDs");
        validateConfigArray(config.requiredScopes(), "Required scopes");
        validateConfigArray(config.requiredAudiences(), "Required audiences");

        logger.info("OnlineTokenValidator '{}' activated", config.name());
    }

    @Override
    @Nullable
    protected TokenValidationResult doValidate(@NotNull String token, @NotNull ClientConnection connection) {
        try {
            // Get introspection endpoint from connection
            String endpoint = getIntrospectionEndpoint(connection);

            if (endpoint == null || endpoint.isEmpty()) {
                logger.debug(
                        "No introspection endpoint available. Configure on OIDC connection or ensure connection uses baseUrl for auto-discovery.");
                return null;
            }

            // Get client credentials for introspection
            ResolvedConnection resolved = ResolvedOidcConnection.resolve(connection);
            if (!(resolved instanceof ResolvedOidcConnection)) {
                logger.debug("Connection is not an OIDC connection");
                return null;
            }

            ResolvedOidcConnection oidcConnection = (ResolvedOidcConnection) resolved;
            String clientId = oidcConnection.clientId();
            String clientSecret = oidcConnection.clientSecret();

            if (clientId == null || clientSecret == null) {
                logger.debug("Client credentials not available for introspection");
                return null;
            }

            // Perform token introspection
            ClientAuthentication clientAuth = new ClientSecretBasic(new ClientID(clientId), new Secret(clientSecret));
            AccessToken accessToken = new BearerAccessToken(token);
            TokenIntrospectionRequest introspectionRequest =
                    new TokenIntrospectionRequest(new URI(endpoint), clientAuth, accessToken);

            HTTPResponse httpResponse = introspectionRequest.toHTTPRequest().send();
            TokenIntrospectionResponse introspectionResponse = TokenIntrospectionResponse.parse(httpResponse);

            if (!introspectionResponse.indicatesSuccess()) {
                logger.debug("Token introspection failed");
                return null;
            }

            TokenIntrospectionSuccessResponse successResponse = introspectionResponse.toSuccessResponse();

            if (!successResponse.isActive()) {
                logger.debug("Token is not active");
                return null;
            }

            // Extract claims from introspection response
            String subject = extractSubject(successResponse);
            if (subject == null || subject.isEmpty()) {
                logger.debug("Token has no subject claim");
                return null;
            }

            // Create a JWTClaimsSet from introspection response for consistency
            JWTClaimsSet claimsSet = buildClaimsSetFromIntrospection(successResponse, subject);

            logger.debug("Token validated successfully (online) for subject: {}", subject);
            return new TokenValidationResult(subject, claimsSet);

        } catch (Exception e) {
            logger.debug("Online token validation failed: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Gets the introspection endpoint from the connection.
     *
     * @param connection the client connection
     * @return the introspection endpoint URL, or {@code null} if not available
     */
    @Nullable
    private String getIntrospectionEndpoint(@NotNull ClientConnection connection) {
        if (connection instanceof OidcConnectionImpl) {
            OidcConnectionImpl oidcConn = (OidcConnectionImpl) connection;
            URI introspectionUri = oidcConn.introspectionEndpoint();
            if (introspectionUri != null) {
                String endpoint = introspectionUri.toString();
                logger.debug("Using introspection endpoint: {}", endpoint);
                return endpoint;
            }
        }
        return null;
    }

    /**
     * Extracts the subject from the introspection response.
     *
     * @param successResponse the successful introspection response
     * @return the subject, or {@code null} if not present
     */
    @Nullable
    private String extractSubject(@NotNull TokenIntrospectionSuccessResponse successResponse) {
        return successResponse.getSubject() != null
                ? successResponse.getSubject().getValue()
                : null;
    }

    /**
     * Builds a JWTClaimsSet from the introspection response.
     *
     * @param successResponse the successful introspection response
     * @param subject the subject to include in the claims set
     * @return the JWT claims set
     */
    @NotNull
    private JWTClaimsSet buildClaimsSetFromIntrospection(
            @NotNull TokenIntrospectionSuccessResponse successResponse, @NotNull String subject) {
        JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder().subject(subject);

        if (successResponse.getIssuer() != null) {
            claimsBuilder.issuer(successResponse.getIssuer().getValue());
        }
        if (successResponse.getExpirationTime() != null) {
            claimsBuilder.expirationTime(successResponse.getExpirationTime());
        }
        if (successResponse.getIssueTime() != null) {
            claimsBuilder.issueTime(successResponse.getIssueTime());
        }
        if (successResponse.getAudience() != null
                && !successResponse.getAudience().isEmpty()) {
            claimsBuilder.audience(successResponse.getAudience().stream()
                    .map(aud -> aud.getValue())
                    .collect(Collectors.toList()));
        }
        if (successResponse.getUsername() != null) {
            claimsBuilder.claim("username", successResponse.getUsername());
        }
        if (successResponse.getScope() != null) {
            claimsBuilder.claim("scope", successResponse.getScope().toString());
        }

        // Extract client_id from the JSON object
        extractClientIdFromJson(successResponse, claimsBuilder);

        return claimsBuilder.build();
    }

    /**
     * Extracts the client_id from the introspection response JSON and adds it to the claims builder.
     *
     * @param successResponse the successful introspection response
     * @param claimsBuilder the claims builder to add the client_id to
     */
    private void extractClientIdFromJson(
            @NotNull TokenIntrospectionSuccessResponse successResponse, @NotNull JWTClaimsSet.Builder claimsBuilder) {
        try {
            JSONObject jsonObject = successResponse.toJSONObject();
            if (jsonObject.containsKey("client_id")) {
                claimsBuilder.claim("client_id", jsonObject.get("client_id").toString());
            }
        } catch (Exception e) {
            logger.debug("Failed to extract client_id from introspection response: {}", e.getMessage());
        }
    }
}
