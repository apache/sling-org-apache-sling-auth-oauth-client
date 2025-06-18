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

import javax.servlet.http.Cookie;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import org.apache.sling.commons.crypto.CryptoService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class RedirectHelper {

    static final String PARAMETER_NAME_REDIRECT = "redirect";

    // We don't want leave the cookie lying around for a long time because it is not needed.
    // At the same time, some OAuth user authentication flows take a long time due to
    // consent, account selection, 2FA, etc. so we cannot make this too short.
    private static final int COOKIE_MAX_AGE_SECONDS = 300;
    private static final Logger logger = LoggerFactory.getLogger(RedirectHelper.class);

    private RedirectHelper() {
        // Utility class
    }

    static @NotNull RedirectTarget buildRedirectTarget(
            @NotNull String[] paths,
            @NotNull URI callbackUri,
            @NotNull ResolvedConnection conn,
            @NotNull OAuthCookieValue oAuthCookieValue,
            @NotNull CryptoService cryptoService) {

        String path = findLongestPathMatching(paths, callbackUri.getPath());

        // Set the cookie with state, connection name, redirect uri, nonce and codeverifier
        Cookie requestKeyCookie = buildCookie(
                path, OAuthCookieValue.COOKIE_NAME_REQUEST_KEY, cryptoService.encrypt(oAuthCookieValue.getValue()));

        // We build th redirect url to be sent to the browser
        URI authorizationEndpointUri = URI.create(conn.authorizationEndpoint());

        // Compose the OpenID authentication request (for the code flow)
        Scope scopes = new Scope(conn.scopes().toArray(new String[0]));
        AuthenticationRequest.Builder authRequestBuilder;
        authRequestBuilder = new AuthenticationRequest.Builder(
                        ResponseType.CODE, scopes, new ClientID(conn.clientId()), callbackUri)
                .endpointURI(authorizationEndpointUri)
                .state(oAuthCookieValue.getState());

        if (oAuthCookieValue.nonce() != null) {
            // For OAuth the nonce is not defined
            authRequestBuilder.nonce(oAuthCookieValue.nonce());
        }

        if (oAuthCookieValue.codeVerifier() != null) {
            // For OAuth and OIDC without PKCE the code verifier is not defined

            CodeVerifier codeVerifier = oAuthCookieValue.codeVerifier();
            authRequestBuilder.codeChallenge(codeVerifier, CodeChallengeMethod.S256);
        }

        List<String[]> parameters = conn.additionalAuthorizationParameters().stream()
                .map(s -> s.split("="))
                .filter(p -> p.length == 2)
                .collect(Collectors.toList());

        for (String[] p : parameters) {
            authRequestBuilder.customParameter(p[0], p[1]);
        }
        URI uri = authRequestBuilder.build().toURI();
        return new RedirectTarget(uri, requestKeyCookie);
    }

    private static @NotNull Cookie buildCookie(@Nullable String path, @NotNull String name, @NotNull String value) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(true);
        cookie.setMaxAge(COOKIE_MAX_AGE_SECONDS);
        if (path != null) cookie.setPath(path);
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

        if (urlPath == null || urlPath.isEmpty()) {
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
