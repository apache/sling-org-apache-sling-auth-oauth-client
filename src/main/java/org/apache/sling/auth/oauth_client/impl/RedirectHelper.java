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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;

class RedirectHelper {

    // We don't want leave the cookie lying around for a long time because it is not needed.
    // At the same time, some OAuth user authentication flows take a long time due to 
    // consent, account selection, 2FA, etc. so we cannot make this too short.
    private static final int COOKIE_MAX_AGE_SECONDS = 300;
    private static final Logger logger = LoggerFactory.getLogger(RedirectHelper.class);
    
    private RedirectHelper() {
        // Utility class
    }

    static @NotNull RedirectTarget buildRedirectTarget(@NotNull String[] paths, @Nullable String originalRedirectTarget, @NotNull ResolvedConnection conn, @NotNull State state,
                                                       @NotNull String perRequestKey, @NotNull URI redirectUri, boolean pkceEnabled, @Nullable String nonce) {

        String path = null;
        if (originalRedirectTarget != null) {
            path = findLongestPathMatching(paths, originalRedirectTarget);
        }

        ArrayList<Cookie> cookies = new ArrayList<>();
        Cookie requestKeyCookie = buildCookie(path, OAuthStateManager.COOKIE_NAME_REQUEST_KEY, perRequestKey);
        cookies.add(requestKeyCookie);

        //-----------------
        URI authorizationEndpointUri = URI.create(conn.authorizationEndpoint());

        // Compose the OpenID authentication request (for the code flow)
        Scope scopes = new Scope(conn.scopes().toArray(new String[0]));
        AuthenticationRequest.Builder authRequestBuilder = new AuthenticationRequest.Builder(
                ResponseType.CODE,
                scopes,
                new ClientID(conn.clientId()),
                redirectUri
        )
        .endpointURI(authorizationEndpointUri)
        .state(state);

        if (nonce != null) {
            Cookie nonceCookie = buildCookie(path, OAuthStateManager.COOKIE_NAME_NONCE, nonce);
            cookies.add(nonceCookie);

            authRequestBuilder.nonce(new Nonce(nonce));

        }

        if (pkceEnabled) {
            // Generate a new random 256 bit code verifier for PKCE
            CodeVerifier codeVerifier = new CodeVerifier();

            authRequestBuilder.codeChallenge(codeVerifier, CodeChallengeMethod.S256);

            Cookie codeVerifierCookie = buildCookie(path, OAuthStateManager.COOKIE_NAME_CODE_VERIFIER, codeVerifier.getValue());
            cookies.add(codeVerifierCookie);
        }

        if (originalRedirectTarget != null) {
            Cookie redirectCookie = buildCookie(path, OAuthStateManager.COOKIE_NAME_REDIRECT_URI, originalRedirectTarget);
            cookies.add(redirectCookie);
        }

        conn.additionalAuthorizationParameters().stream()
                .map(s -> s.split("="))
                .filter(p -> p.length == 2)
                .forEach(p -> authRequestBuilder.customParameter(p[0], p[1]));
        URI uri = authRequestBuilder.build().toURI();
        return new RedirectTarget(uri, cookies);
    }

    
    private static @NotNull Cookie buildCookie(@Nullable String path, @NotNull String name, @NotNull String perRequestKey) {
        Cookie cookie = new Cookie(name, perRequestKey);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(COOKIE_MAX_AGE_SECONDS);
        if (path !=null)
            cookie.setPath(path);
        return cookie;
    }

    static @Nullable String findLongestPathMatching(@NotNull String[] paths, @Nullable String url) {

        if (url == null || url.isEmpty() || paths.length == 0) {
            return null;
        }

        String urlPath;
        try {
            urlPath = new URI(url).getPath();
        } catch (URISyntaxException e) {
            logger.debug("findLongestPathMatching: Invalid URL {}", url, e);
            return null;
        }

        if (urlPath == null || urlPath.isEmpty())  {
            return null;
        }

        String longestPath = null;
        for (String p : paths) {
            if (isDescendantOrEqual(p, urlPath) && (longestPath == null || p.length() > longestPath.length())) {
                longestPath = p;
            }
        }
        return longestPath;
    }

    // copied from org.apache.jackrabbit.util.Text
    private static boolean isDescendantOrEqual(String path, String descendant) {
        if (path.equals(descendant)) {
            return true;
        } else {
            String pattern = path.endsWith("/") ? path : path + "/";
            return descendant.startsWith(pattern);
        }
    }

}