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

import javax.jcr.PropertyType;
import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.Value;
import javax.jcr.ValueFactory;

import java.time.ZonedDateTime;
import java.util.Calendar;
import java.util.GregorianCalendar;

import org.apache.jackrabbit.api.JackrabbitSession;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.commons.crypto.CryptoService;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.osgi.service.component.annotations.ConfigurationPolicy.REQUIRE;

// a config class is intentionally not defined, but a config is required to select an implementation
@Component(configurationPolicy = REQUIRE)
public class JcrUserHomeOAuthTokenStore implements OAuthTokenStore {

    private static final String PROPERTY_NAME_EXPIRES_AT = "expires_at";
    private static final String PROPERTY_NAME_REFRESH_TOKEN = "refresh_token";

    private static final Logger logger = LoggerFactory.getLogger(JcrUserHomeOAuthTokenStore.class);

    private final CryptoService cryptoService;

    @Activate
    public JcrUserHomeOAuthTokenStore(@Reference CryptoService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @Override
    public @NotNull OAuthToken getAccessToken(
            @NotNull ClientConnection connection, @NotNull ResourceResolver resolver) {
        try {
            User user = adaptToUser(resolver);
            Value[] expiresAt = user.getProperty(propertyPath(connection, PROPERTY_NAME_EXPIRES_AT));
            if (expiresAt != null && expiresAt.length == 1 && expiresAt[0].getType() == PropertyType.DATE) {
                Calendar expiresCal = expiresAt[0].getDate();
                if (expiresCal.before(Calendar.getInstance())) {
                    logger.info("Token for {} expired at {}, marking as expired", connection.name(), expiresCal);

                    // refresh token is present, mark as expired
                    return new OAuthToken(TokenState.EXPIRED, null);
                }
            }

            return getToken(connection, user, PROPERTY_NAME_ACCESS_TOKEN);
        } catch (RepositoryException e) {
            throw new OAuthException(e);
        }
    }

    private @NotNull OAuthToken getToken(
            @NotNull ClientConnection connection, @NotNull User user, @NotNull String propertyName)
            throws RepositoryException {

        Value[] tokenValue = user.getProperty(propertyPath(connection, propertyName));
        if (tokenValue == null) return new OAuthToken(TokenState.MISSING, null);

        if (tokenValue.length != 1)
            throw new OAuthException(
                    String.format("Unexpected value count %d for token property %s", tokenValue.length, propertyName));

        String encryptedValue = tokenValue[0].getString();

        return new OAuthToken(TokenState.VALID, cryptoService.decrypt(encryptedValue));
    }

    @Override
    public @NotNull OAuthToken getRefreshToken(
            @NotNull ClientConnection connection, @NotNull ResourceResolver resolver) {
        try {
            User user = adaptToUser(resolver);
            return getToken(connection, user, PROPERTY_NAME_REFRESH_TOKEN);
        } catch (RepositoryException e) {
            throw new OAuthException(e);
        }
    }

    @Override
    public void persistTokens(
            @NotNull ClientConnection connection, @NotNull ResourceResolver resolver, @NotNull OAuthTokens tokens) {
        try {
            User user = adaptToUser(resolver);
            Session session = adaptToSession(resolver);
            ValueFactory vf = session.getValueFactory();

            setTokenProperty(user, vf, propertyPath(connection, PROPERTY_NAME_ACCESS_TOKEN), tokens.accessToken());
            setTokenProperty(user, vf, propertyPath(connection, PROPERTY_NAME_REFRESH_TOKEN), tokens.refreshToken());

            ZonedDateTime expiry = null;
            long expiresAt = tokens.expiresAt();
            if (expiresAt > 0) {
                expiry = ZonedDateTime.now().plusSeconds(expiresAt);
            }
            if (expiry != null) {
                Calendar cal = GregorianCalendar.from(expiry);
                user.setProperty(propertyPath(connection, PROPERTY_NAME_EXPIRES_AT), vf.createValue(cal));
            } else {
                user.removeProperty(propertyPath(connection, PROPERTY_NAME_EXPIRES_AT));
            }

            session.save();
        } catch (RepositoryException e) {
            throw new OAuthException(e);
        }
    }

    @Override
    public void clearAccessToken(@NotNull ClientConnection connection, @NotNull ResourceResolver resolver)
            throws OAuthException {
        try {
            User currentUser = adaptToUser(resolver);

            currentUser.removeProperty(propertyPath(connection, PROPERTY_NAME_ACCESS_TOKEN));
            currentUser.removeProperty(propertyPath(connection, PROPERTY_NAME_EXPIRES_AT));
            // TODO: need to remove refresh token as well?

            adaptToSession(resolver).save();
        } catch (RepositoryException e) {
            throw new OAuthException(e);
        }
    }

    @Override
    public @Nullable String getIdToken(
            @NotNull ClientConnection connection, @NotNull Session serviceSession, @NotNull String userId)
            throws OAuthException {
        // Sanitize userId for safe logging (prevents log injection)
        String safeUserId = userId.replace('\n', '_').replace('\r', '_');
        try {
            if (!(serviceSession instanceof JackrabbitSession)) {
                logger.warn(
                        "Service session is not a JackrabbitSession; cannot retrieve id_token for user {}", safeUserId);
                return null;
            }

            UserManager userManager = ((JackrabbitSession) serviceSession).getUserManager();
            Authorizable authorizable = userManager.getAuthorizable(userId);

            if (authorizable == null || authorizable.isGroup()) {
                logger.debug("User {} not found or is a group; cannot read id_token from Oak", safeUserId);
                return null;
            }

            // Try multiple property paths: oauth-tokens/{connection}/id_token (stored by persistTokens),
            // then profile/id_token (common when sync stores on profile), then id_token (bare name)
            for (String relPath : new String[] {
                propertyPath(connection, PROPERTY_NAME_ID_TOKEN),
                PROFILE_PREFIX + PROPERTY_NAME_ID_TOKEN,
                PROPERTY_NAME_ID_TOKEN
            }) {
                String encrypted = readEncryptedProperty(authorizable, relPath);
                if (encrypted != null) {
                    return decryptIdToken(encrypted, safeUserId);
                }
            }

            logger.debug("No id_token found for user {} in Oak (storeIdToken and sync must persist it)", safeUserId);
            return null;
        } catch (RepositoryException e) {
            throw new OAuthException(
                    "Repository error reading id_token for user '" + safeUserId
                            + "'. Verify service user has read access to user profiles.",
                    e);
        }
    }

    private @Nullable String readEncryptedProperty(@NotNull Authorizable authorizable, @NotNull String relPath)
            throws RepositoryException {
        if (!authorizable.hasProperty(relPath)) return null;
        Value[] values = authorizable.getProperty(relPath);
        if (values == null || values.length == 0) return null;
        String encrypted = values[0].getString();
        return (encrypted != null && !encrypted.isEmpty()) ? encrypted : null;
    }

    private @Nullable String decryptIdToken(@NotNull String encrypted, @NotNull String safeUserId) {
        try {
            String decrypted = cryptoService.decrypt(encrypted);
            logger.debug("Successfully retrieved and decrypted id_token for user {}", safeUserId);
            return decrypted;
        } catch (Exception e) {
            logger.error(
                    "Failed to decrypt id_token for user {}. IdP may not properly invalidate session. Error: {}",
                    safeUserId,
                    e.getMessage(),
                    e);
            return null;
        }
    }

    private void setTokenProperty(
            @NotNull User user,
            @NotNull ValueFactory valueFactory,
            @NotNull String propertyPath,
            @Nullable String value)
            throws RepositoryException {
        if (value != null) {
            user.setProperty(propertyPath, createTokenValue(valueFactory, value));
        } else {
            // TODO: verify if removing the property is the intended behavior in case of null accessToken
            logger.info("Token value is null, removing property {}", propertyPath);
            user.removeProperty(propertyPath);
        }
    }

    private @NotNull Value createTokenValue(@NotNull ValueFactory valueFactory, @NotNull String propertyValue) {
        String encryptedValue = cryptoService.encrypt(propertyValue);
        return valueFactory.createValue(encryptedValue);
    }

    private static @NotNull String propertyPath(@NotNull ClientConnection connection, @NotNull String propertyName) {
        return nodePath(connection) + "/" + propertyName;
    }

    private static @NotNull String nodePath(@NotNull ClientConnection connection) {
        return "oauth-tokens/" + connection.name();
    }

    private static @NotNull User adaptToUser(@NotNull ResourceResolver resolver) {
        User user = resolver.adaptTo(User.class);
        if (user == null) {
            throw new OAuthException("Unable to adapt resolver to a user.");
        }
        return user;
    }

    private static @NotNull Session adaptToSession(@NotNull ResourceResolver resolver) {
        Session session = resolver.adaptTo(Session.class);
        if (session == null) {
            throw new OAuthException("Unable to adapt resolver to a session.");
        }
        return session;
    }
}
