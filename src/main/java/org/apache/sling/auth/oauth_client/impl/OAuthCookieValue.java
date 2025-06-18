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

import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.openid.connect.sdk.Nonce;
import org.apache.sling.commons.crypto.CryptoService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OAuthCookieValue {

    public static final String COOKIE_NAME_REQUEST_KEY = "sling.oauth-request-key";

    private final @NotNull String perRequestKey;
    private final @NotNull String connectionName;

    // This is NOT the callback URL, but the URL to which the user should be redirected after the OAuth flow is
    // completed.
    private final @Nullable String redirect;
    private @Nullable Nonce nonce;
    private @Nullable CodeVerifier codeVerifier;
    private static final Logger logger = LoggerFactory.getLogger(OAuthCookieValue.class);

    public static final int STATE_INDEX = 0;
    public static final int CONNECTION_NAME_INDEX = 1;
    public static final int REDIRECT_INDEX = 2;
    public static final int NONCE_INDEX = 3;
    public static final int CODE_VERIFIER_INDEX = 4;

    public OAuthCookieValue(@NotNull String perRequestKey, @NotNull String connectionName, @Nullable String redirect) {
        this.perRequestKey = perRequestKey;
        this.connectionName = connectionName;
        this.redirect = redirect;
    }

    public OAuthCookieValue(
            @NotNull String perRequestKey,
            @NotNull String connectionName,
            @Nullable String redirect,
            @NotNull Nonce nonce,
            @Nullable CodeVerifier codeVerifier) {
        this.perRequestKey = perRequestKey;
        this.connectionName = connectionName;
        this.redirect = redirect;
        this.nonce = nonce;
        this.codeVerifier = codeVerifier;
    }

    public OAuthCookieValue(@NotNull String encyptedValue, @NotNull CryptoService cryptoService) {
        String decryptedValue = cryptoService.decrypt(encyptedValue);
        String[] parts = decryptedValue.split("\\|");
        if (parts.length < 2) {
            logger.error("Invalid OAuthCookieValue format: {}", decryptedValue);
            throw new IllegalArgumentException("Invalid OAuthCookieValue format");
        }
        // We have minimum 2 parts
        this.perRequestKey = parts[STATE_INDEX];
        this.connectionName = parts[CONNECTION_NAME_INDEX];

        // We can have also the redirect
        if (parts.length > 2) {
            this.redirect = parts[REDIRECT_INDEX].isEmpty() ? null : parts[REDIRECT_INDEX];
        } else {
            this.redirect = null;
        }

        // In OIDC we always also have nonce
        if (parts.length > 3) {
            this.nonce = parts[NONCE_INDEX].isEmpty() ? null : new Nonce(parts[NONCE_INDEX]);
        }

        // In OIDC with PKCE we also have code verifier
        if (parts.length > 4) {
            this.codeVerifier =
                    parts[CODE_VERIFIER_INDEX].isEmpty() ? null : new CodeVerifier(parts[CODE_VERIFIER_INDEX]);
        }
    }

    public @NotNull String perRequestKey() {
        return perRequestKey;
    }

    public @NotNull State getState() {
        return new State(perRequestKey);
    }

    public @NotNull String connectionName() {
        return connectionName;
    }

    public @Nullable String redirect() {
        return redirect;
    }

    public @Nullable Nonce nonce() {
        return nonce;
    }

    public @Nullable CodeVerifier codeVerifier() {
        return codeVerifier;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OAuthCookieValue)) return false;

        OAuthCookieValue that = (OAuthCookieValue) o;

        if (!perRequestKey.equals(that.perRequestKey)) return false;
        if (!connectionName.equals(that.connectionName)) return false;
        if (redirect != null ? !redirect.equals(that.redirect) : that.redirect != null) return false;
        if (nonce != null ? !nonce.equals(that.nonce) : that.nonce != null) return false;
        if (codeVerifier != null ? !codeVerifier.equals(that.codeVerifier) : that.codeVerifier != null) return false;

        return true;
    }

    @Override
    public int hashCode() {
        int result = perRequestKey.hashCode();
        result = 31 * result + connectionName.hashCode();
        result = 31 * result + (redirect != null ? redirect.hashCode() : 0);
        result = 31 * result + (nonce != null ? nonce.hashCode() : 0);
        result = 31 * result + (codeVerifier != null ? codeVerifier.hashCode() : 0);
        return result;
    }

    public @NotNull String getValue() {
        return perRequestKey
                + '|'
                + connectionName
                + '|'
                + (redirect == null ? "" : redirect)
                + '|'
                + (nonce == null ? "" : nonce.getValue())
                + '|'
                + (codeVerifier == null ? "" : codeVerifier.getValue());
    }
}
