/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.sling.auth.oauth_client.impl;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.servlet.http.Cookie;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

class RedirectHelper {

    // We don't want leave the cookie lying around for a long time because it is not needed.
    // At the same time, some OAuth user authentication flows take a long time due to 
    // consent, account selection, 2FA, etc. so we cannot make this too short.
    private static final int COOKIE_MAX_AGE_SECONDS = 300;
    
    private RedirectHelper() {
        // Utility class
    }
    
    static @NotNull RedirectTarget buildRedirectTarget(@NotNull ClientID clientID, @NotNull String authorizationEndpoint, @NotNull List<String> scopes,
                                                       @Nullable List<String> additionalAuthorizationParameters, @NotNull State state,
                                                       @NotNull String perRequestKey, @NotNull URI redirectUri, boolean pkceEnabled, @Nullable String nonce) {

        ArrayList<Cookie> cookies = new ArrayList<>();
        Cookie requestKeyCookie = buildCookie(OAuthStateManager.COOKIE_NAME_REQUEST_KEY, perRequestKey);
        cookies.add(requestKeyCookie);

        //-----------------
        URI authorizationEndpointUri = URI.create(authorizationEndpoint);

        // Compose the OpenID authentication request (for the code flow)
        AuthenticationRequest.Builder authRequestBuilder = new AuthenticationRequest.Builder(
                ResponseType.CODE,
                new Scope(scopes.toArray(new String[scopes.size()])),
                clientID,
                redirectUri
        )
        .endpointURI(authorizationEndpointUri)
        .state(state);

        if (nonce != null) {
            Cookie nonceCookie = buildCookie(OAuthStateManager.COOKIE_NAME_NONCE, nonce);
            cookies.add(nonceCookie);

            authRequestBuilder.nonce(new Nonce(nonce));

        }

        if (pkceEnabled) {
            // Generate a new random 256 bit code verifier for PKCE
            CodeVerifier codeVerifier = new CodeVerifier();

            authRequestBuilder.codeChallenge(codeVerifier, CodeChallengeMethod.S256);

            Cookie codeVerifierCookie = buildCookie(OAuthStateManager.COOKIE_NAME_CODE_VERIFIER, codeVerifier.getValue());
            cookies.add(codeVerifierCookie);
        }

        if (additionalAuthorizationParameters != null) {
            additionalAuthorizationParameters.stream()
                    .map(s -> s.split("="))
                    .filter(p -> p.length == 2)
                    .forEach(p -> authRequestBuilder.customParameter(p[0], p[1]));
        }
        URI uri = authRequestBuilder.build().toURI();
        return new RedirectTarget(uri, cookies.toArray(new Cookie[cookies.size()]));
    }

    
    private static @NotNull Cookie buildCookie(@NotNull String name, @NotNull String perRequestKey) {
        Cookie cookie = new Cookie(name, perRequestKey);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(COOKIE_MAX_AGE_SECONDS);
        return cookie;
    }

}