/*
 * Licensed to the Sakai Foundation (SF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The SF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONObject;
import net.minidev.json.JSONValue;
import net.minidev.json.JSONArray;
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
        immediate = true,
        property = {
                "service.ranking:Integer=10"
        }
)
@Designate(ocd = SlingUserInfoProcessorImpl.Config.class)
public class SlingUserInfoProcessorImpl implements UserInfoProcessor {

    @ObjectClassDefinition(
            name = "Apache Sling Oidc UserInfo Processor",
            description = "Apache Sling Oidc UserInfo Processor Service"
    )
    @interface Config {
        @AttributeDefinition(
                name = "storeAccessToken",
                description = "Store access Token under User Node"
        )
        boolean storeAccessToken() default false;
        @AttributeDefinition(
                name = "storeRefreshToken",
                description = "Store access Refresh under User Node"
        )
        boolean storeRefreshToken() default false;
    }
    
    private static final Logger logger = LoggerFactory.getLogger(SlingUserInfoProcessorImpl.class);

    private final CryptoService cryptoService;
    private final boolean storeAccessToken;
    private final boolean storeRefreshToken;

    @Activate
    public SlingUserInfoProcessorImpl(@Reference(policyOption = ReferencePolicyOption.GREEDY) CryptoService service, Config config) {
        this.cryptoService = service;
        this.storeAccessToken = config.storeAccessToken();
        this.storeRefreshToken = config.storeRefreshToken();
    }
    
    @Override
    public @NotNull OidcAuthCredentials process(@Nullable String stringUserInfo, @NotNull String stringTokenResponse,
                                                @NotNull String oidcSubject, @NotNull String idp) {

        TokenResponse tokenResponse = parseTokenResponse(stringTokenResponse);
        UserInfo userInfo = parseUserInfo(stringUserInfo);
        OAuthTokens tokens = Converter.toSlingOAuthTokens(tokenResponse.toSuccessResponse().getTokens());

        // Create AuthenticationInfo object
        OidcAuthCredentials credentials = new OidcAuthCredentials(oidcSubject, idp);
        credentials.setAttribute(".token", "");

        if (userInfo != null) {
            logger.debug("Preferred Username: {}", userInfo.getPreferredUsername());
            logger.debug("Subject: {}", userInfo.getSubject());
            logger.debug("Email: {}", userInfo.getEmailAddress());
            logger.debug("Name: {}", userInfo.getGivenName());
            logger.debug("FamilyName: {}", userInfo.getFamilyName());

            Object groups = userInfo.toJSONObject().remove("groups");
            if (groups instanceof JSONArray) {
                JSONArray groupJsonArray = (JSONArray) groups;
                logger.debug("Groups: {}", groups);
                //Convert the groups in a Set of Strings
                groupJsonArray.forEach(group -> credentials.addGroup(group.toString()));
            }

            // Set all the attributes in userInfo to the credentials
            userInfo.toJSONObject().forEach((key, value) -> {
                if (value != null) {
                    credentials.setAttribute("profile/" + key, value.toString());
                }
            });
        }
        //Store the Access Token on user node
        String accessToken = tokens.accessToken();
        if (storeAccessToken && accessToken != null) {
            credentials.setAttribute(OAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN, cryptoService.encrypt(accessToken));
        } else {
            logger.debug("Access Token is null, omit adding as credentials attribute '{}'", OAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN);
        }

        //Store the Refresh Token on user node
        String refreshToken = tokens.accessToken();
        if (storeRefreshToken && refreshToken != null) {
            credentials.setAttribute(OAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN, cryptoService.encrypt(refreshToken));
        } else {
            logger.debug("Refresh Token is null, omit adding as credentials attribute '{}'", OAuthTokenStore.PROPERTY_NAME_REFRESH_TOKEN);
        }

        return credentials;
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
            return TokenResponse.parse(jsonTokenResponse);
        } catch (ParseException e) {
            throw new RuntimeException("Failed to parse TokenResponse in UserInfoProcessor", e);
        }
    }
}
