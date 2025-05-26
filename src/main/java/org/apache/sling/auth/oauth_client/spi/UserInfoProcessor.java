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
package org.apache.sling.auth.oauth_client.spi;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * Process the user info received from the identity provider and return the credentials that will be returned by the authentication handler.
 * This interface can be implemented to perform custom processing of the user info, such as mapping fields to a specific format or extracting additional information,
 * or to perform other operation with the released tokens.
 */
public interface UserInfoProcessor {

    /**
     *
     *  <p>This method is called by the OIDC authentication handler after the user info and token response have been received from the identity provider.</p>
     *
     * @param userInfo the user info received from the identity provider, may be null if not available. See: https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
     * @param tokenResponse the token response received from the identity provider, must not be null. See: https://openid.net/specs/openid-connect-core-1_0.html#HybridTokenResponse
     * @param oidcSubject the OIDC subject identifier as defined in ID Token, must not be null
     * @param idp the identity provider identifier as defined in OidcAuthenticationHandler configuration, must not be null
     * @return the credentials to be returned by the authentication handler, must not be null
     *
     * @param userInfo
     * @param tokenResponse
     * @param oidcSubject
     * @param idp
     * @return
     */
    @NotNull OidcAuthCredentials process(@Nullable String userInfo, @NotNull String tokenResponse,
                                         @NotNull String oidcSubject, @NotNull String idp);
}
