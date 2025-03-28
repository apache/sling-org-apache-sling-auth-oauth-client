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

import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import net.minidev.json.JSONArray;
import org.apache.sling.auth.oauth_client.OAuthTokens;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.auth.oauth_client.spi.UserInfoProcessor;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(
        service = UserInfoProcessor.class,
        immediate = true,
        property = {
                "service.ranking:Integer=10"
        }
)
public class UserInfoProcessorImpl implements UserInfoProcessor {

    Logger logger = LoggerFactory.getLogger(UserInfoProcessorImpl.class);

    @Override
    public OidcAuthCredentials process(UserInfo userInfo, TokenResponse tokenResponse, String idp) {
        logger.debug("Prefered Username: " + userInfo.getPreferredUsername());
        logger.debug("Subject: " + userInfo.getSubject());
        logger.debug("Email: " + userInfo.getEmailAddress());
        logger.debug("Name: " + userInfo.getGivenName());
        logger.debug("FamilyName: " + userInfo.getFamilyName());
        OAuthTokens tokens = Converter.toSlingOAuthTokens(tokenResponse.toSuccessResponse().getTokens());

        // Create AuthenticationInfo object
        OidcAuthCredentials credentials = new OidcAuthCredentials(userInfo.getPreferredUsername(), idp);
        credentials.setAttribute(".token", "");

        Object groups = userInfo.toJSONObject().remove("groups");
        if (groups != null && groups instanceof JSONArray) {
            logger.debug("Groups: " + groups.toString());
            //Convert the groups in a Set of Strings
            ((JSONArray) groups).forEach(group -> credentials.addGroup(group.toString()));

        }

        // Set all the attributes in userInfo to the credentials
        userInfo.toJSONObject().forEach((key, value) -> {
            if (value != null) {
                credentials.setAttribute("profile/"+key, value.toString());
            }
        });

        //Store the Access Token on user node
        credentials.setAttribute(JcrUserHomeOAuthTokenStore.PROPERTY_NAME_ACCESS_TOKEN, tokens.accessToken());
        return credentials;
    }

    @Override
    public String getSubject(UserInfo userInfo) {
        return userInfo.getSubject().getValue();
    }


}
