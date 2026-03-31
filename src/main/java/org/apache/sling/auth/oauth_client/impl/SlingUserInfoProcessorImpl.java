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

import java.util.List;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.apache.sling.commons.crypto.CryptoService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
        service = UserInfoProcessor.class,
        property = {"service.ranking:Integer=10"})
@Designate(ocd = SlingUserInfoProcessorImpl.Config.class, factory = true)
public class SlingUserInfoProcessorImpl implements UserInfoProcessor {

    @ObjectClassDefinition(
            name = "Apache Sling Oidc UserInfo Processor",
            description = "Apache Sling Oidc UserInfo Processor Service")
    @interface Config {

        @AttributeDefinition(name = "groupsInIdToken", description = "Read groups from ID Token")
        boolean groupsInIdToken() default false;

        @AttributeDefinition(name = "storeAccessToken", description = "Store access Token under User Node")
        boolean storeAccessToken() default false;

        @AttributeDefinition(name = "storeRefreshToken", description = "Store access Refresh under User Node")
        boolean storeRefreshToken() default false;

        @AttributeDefinition(
                name = "storeIdToken",
                description =
                        "Store the ID Token in credentials for use during logout (id_token_hint at IdP end_session_endpoint). "
                                + "Requires the login cookie manager to persist it (e.g. SlingLoginCookieManager).")
        boolean storeIdToken() default false;

        @AttributeDefinition(
                name = "groupsClaimName",
                description = "Name of the claim in the ID Token or UserInfo that contains the groups. "
                        + "If not set, the default 'groups' is used")
        String groupsClaimName() default "groups";

        @AttributeDefinition(name = "connection", description = "OIDC Connection Name")
        String connection();

        @AttributeDefinition(
                name = "idpNameInPrincipals",
                description = "Add a suffix with the idp in the username and to the groups created by this processor")
        boolean idpNameInPrincipals() default false;
    }

    private static final Logger logger = LoggerFactory.getLogger(SlingUserInfoProcessorImpl.class);

    private final CryptoService cryptoService;
    private final boolean storeAccessToken;
    private final boolean storeRefreshToken;
    private final boolean storeIdToken;
    private final boolean groupsInIdToken;
    private final String groupsClaimName;
    private final String connection;
    private final boolean idpNameInPrincipals;

    @Activate
    public SlingUserInfoProcessorImpl(
            @Reference(policyOption = ReferencePolicyOption.GREEDY) CryptoService service, Config config) {
        this.cryptoService = service;
        this.storeAccessToken = config.storeAccessToken();
        this.storeRefreshToken = config.storeRefreshToken();
        this.storeIdToken = config.storeIdToken();
        this.groupsInIdToken = config.groupsInIdToken();
        this.groupsClaimName = config.groupsClaimName();
        if (config.connection() == null || config.connection().isEmpty()) {
            throw new IllegalArgumentException("Connection name must not be null or empty");
        }
        this.connection = config.connection();
        this.idpNameInPrincipals = config.idpNameInPrincipals();
    }

    @Override
    public @NotNull OidcAuthCredentials process(
            @Nullable String stringUserInfo,
            @NotNull String stringTokenResponse,
            @NotNull String oidcSubject,
            @NotNull String idp) {

        TokenResponse tokenResponse = parseTokenResponse(stringTokenResponse);
        UserInfo userInfo = parseUserInfo(stringUserInfo);
        OAuthTokens tokens =
                Converter.toSlingOAuthTokens(tokenResponse.toSuccessResponse().getTokens());

        // Create AuthenticationInfo object
        OidcAuthCredentials credentials =
                new OidcAuthCredentials(oidcSubject + (idpNameInPrincipals ? ";" + idp : ""), idp);
        credentials.setAttribute(".token", "");

        if (userInfo != null) {
            logger.debug("Preferred Username: {}", userInfo.getPreferredUsername());
            logger.debug("Subject: {}", userInfo.getSubject());
            logger.debug("Email: {}", userInfo.getEmailAddress());
            logger.debug("Name: {}", userInfo.getGivenName());
            logger.debug("FamilyName: {}", userInfo.getFamilyName());

            // If groups are not in ID Token, add them from UserInfo
            userInfo.toJSONObject().forEach((key, value) -> {
                if (value != null) {
                    credentials.setAttribute(OAuthTokenStore.PROFILE_PREFIX + key, value.toString());
                }
            });
        }

        if (groupsInIdToken) {
            // If groups are in ID Token, add them to the credentials
            Object groups = Converter.extractIdTokenClaim(tokens.idToken(), groupsClaimName);
            if (groups instanceof List) {
                logger.debug("Groups from ID Token: {}", groups);
                ((List) groups).forEach(group -> credentials.addGroup(getGroupName(idp, group)));
            }
        } else if (userInfo != null) {
            // If groups are not in ID Token, check UserInfo for groups
            Object groups = userInfo.toJSONObject().remove(groupsClaimName);
            if (groups instanceof JSONArray) {
                JSONArray groupJsonArray = (JSONArray) groups;
                logger.debug("Groups: {}", groups);
                // Convert the groups in a Set of Strings
                groupJsonArray.forEach(group -> credentials.addGroup(getGroupName(idp, group)));
            }
        }
        // Store the Access Token on user node
        String accessToken = tokens.accessToken();
        if (storeAccessToken && accessToken != null) {
            credentials.setAttribute(OAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN, cryptoService.encrypt(accessToken));
        } else {
            logger.debug(
                    "Access Token is null, omit adding as credentials attribute '{}'",
                    OAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN);
        }

        // Store the Refresh Token on user node
        String refreshToken = tokens.refreshToken();
        if (storeRefreshToken && refreshToken != null) {
            credentials.setAttribute(OAuthTokenStore.PROPERTY_NAME_REFRESH_TOKEN, cryptoService.encrypt(refreshToken));
        } else {
            logger.debug(
                    "Refresh Token is null, omit adding as credentials attribute '{}'",
                    OAuthTokenStore.PROPERTY_NAME_REFRESH_TOKEN);
        }

        // Store the ID Token for logout (id_token_hint at IdP end_session_endpoint)
        // SECURITY NOTE: The ID token is encrypted before storage but increases the attack surface.
        // Ensure proper access controls on user profile storage and rotation of encryption keys.
        String idToken = tokens.idToken();
        if (storeIdToken && idToken != null && !idToken.isEmpty()) {
            try {
                credentials.setAttribute(OAuthTokenStore.PROPERTY_NAME_ID_TOKEN, cryptoService.encrypt(idToken));
                logger.debug("ID token stored (encrypted) for logout support");
            } catch (RuntimeException e) {
                logger.error("Failed to encrypt ID token for logout: {}", e.getMessage(), e);
            }
        } else if (storeIdToken) {
            logger.debug("ID token is null or empty; cannot store for logout");
        }

        // The returned credentials are passed to Oak's LoginModule, which delegates to a registered
        // SynchronizationHandler (e.g. DefaultSyncHandler) to create or update the JCR user and
        // synchronize group memberships based on the attributes and groups set above.
        return credentials;
    }

    @NotNull
    private String getGroupName(@NotNull String idp, Object group) {
        return group.toString() + (idpNameInPrincipals ? ";" + idp : "");
    }

    private static @Nullable UserInfo parseUserInfo(@Nullable String stringUserInfo) {
        if (stringUserInfo != null) {
            try {
                return UserInfo.parse(stringUserInfo);
            } catch (ParseException e) {
                throw new RuntimeException("Failed to parse UserInfo in UserInfoProcessor", e);
            }
        }
        return null;
    }

    private static @NotNull TokenResponse parseTokenResponse(@NotNull String stringTokenResponse) {
        try {
            JSONObject jsonTokenResponse = (JSONObject) JSONValue.parse(stringTokenResponse);
            return OIDCTokenResponse.parse(jsonTokenResponse);
        } catch (ParseException e) {
            throw new RuntimeException("Failed to parse TokenResponse in UserInfoProcessor", e);
        }
    }

    @Override
    public @NotNull String connection() {
        return connection;
    }
}
