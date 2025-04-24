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

import org.apache.commons.codec.binary.Base64;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.oauth_client.spi.LoginCookieManager;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Credentials;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

@Component(
        service = LoginCookieManager.class,
        immediate = true,
        property = {
                "service.ranking:Integer=10"
        }
)
public class SlingLoginCookieManager implements LoginCookieManager {

    private static final Logger log = LoggerFactory.getLogger(SlingLoginCookieManager.class);
    private TokenStore tokenStore;
    private long sessionTimeout;
    private String cookieName;

    @ObjectClassDefinition(
            name = "Apache Sling Token Update Configuration for OIDC Authentication Handler",
            description = "Apache Sling Token Update Configuration for OIDC Authentication Handler"
    )

    @interface SlingLoginCookieManagerConfig {
        @AttributeDefinition(name = "tokenFile",
                description = "Token File")
        String tokenFile() default "cookie-tokens.bin";

        @AttributeDefinition(name = "form_token_fastseed",
                description = "Form Token Fast Seed")
        boolean form_token_fastseed() default false;

        @AttributeDefinition(name = "sessionTimeout",
                description = "Session Timeout")
        long sessionTimeout() default 8 * 60 * 60 * 1000;

        @AttributeDefinition(name = "cookieName",
                description = "Cookie Name")
        String cookieName() default "sling.oidcauth";
    }

    @Activate
    public SlingLoginCookieManager(SlingLoginCookieManagerConfig config, BundleContext bundleContext)
            throws InvalidKeyException, NoSuchAlgorithmException, IllegalStateException {
        final String tokenFileName = config.tokenFile();
        final File tokenFile = getTokenFile(tokenFileName, bundleContext);
        final boolean fastSeed = config.form_token_fastseed();
        log.info("Storing tokens in {}", tokenFile.getAbsolutePath());

        this.tokenStore = new TokenStore(tokenFile, sessionTimeout, fastSeed);
        this.sessionTimeout = config.sessionTimeout();
        this.cookieName = config.cookieName();
    }
    @Override
    public void setLoginCookie(@NotNull HttpServletRequest request, @NotNull HttpServletResponse response, 
                               @NotNull SlingRepository repository, @NotNull Credentials creds) {

        long expires = System.currentTimeMillis() + this.sessionTimeout;

        // get current authentication data, may be missing after first login
        String authData = null;
        try {
            authData = tokenStore.encode(expires, ((OidcAuthCredentials)creds).getUserId());
        } catch (NoSuchAlgorithmException|InvalidKeyException e) {
            throw new RuntimeException(e);
        } 
        String cookieValue = Base64.encodeBase64URLSafeString(authData.getBytes(StandardCharsets.UTF_8));
        setCookie(request, response, cookieName, cookieValue, (int) (sessionTimeout / 1000));
    }

    @Override
    @Nullable public AuthenticationInfo verifyLoginCookie(@NotNull HttpServletRequest request) {
        Cookie cookie = getLoginCookie(request);
        if (cookie == null) {
            return null;
        }
        String cookieValue = cookie.getValue();
        if (cookieValue.isEmpty()) {
            return null;
        }
        String decodedCookieValue = new String(Base64.decodeBase64(cookieValue), StandardCharsets.UTF_8);
        if (tokenStore.isValid(decodedCookieValue)) {
            return createAuthInfo(decodedCookieValue);
        }
        return null;
    }

    @Override
    public @Nullable Cookie getLoginCookie(@NotNull HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (this.cookieName.equals(cookie.getName())) {
                return cookie;
            }
        }
        return null;
    }

    private @Nullable AuthenticationInfo createAuthInfo(@NotNull final String authData) {
        final String userId = getUserId(authData);
        if (userId == null) {
            return null;
        }

        OidcAuthCredentials credentials = new OidcAuthCredentials(userId, "oidc");
        credentials.setAttribute(".token", "");

        AuthenticationInfo authInfo = new AuthenticationInfo("oidc", userId);
        authInfo.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);

        return authInfo;
    }

    @Nullable String getUserId(@NotNull final String authData) {
        String[] parts = TokenStore.split(authData);
        if (parts.length == 3) {
            return parts[2];
        }
        return null;
    }

    private static void setCookie(@NotNull final HttpServletRequest request, @NotNull final HttpServletResponse response, 
                           @NotNull final String name, @NotNull final String value, final int maxAge) {
        // set the cookie
        final StringBuilder cookie = new StringBuilder(name);
        cookie.append('=');
        cookie.append(value);
        cookie.append("; Path=/; HttpOnly");
        if (maxAge >= 0) {
            cookie.append("; Max-Age=");
            cookie.append(maxAge);
        }
        cookie.append("; SameSite=Lax");
        if (request.isSecure()) {
            cookie.append("; Secure");
        }
        response.addHeader("Set-Cookie", cookie.toString());
    }

    /**
     * Returns an absolute file indicating the file to use to persist the security
    4 * tokens.
     * <p>
     * This method is not part of the API of this class and is package private to
     * enable unit tests.
     *
     * @param tokenFileName
     *            The configured file name, must not be null
     * @param bundleContext
     *            The BundleContext to use to make an relative file absolute
     * @return The absolute file
     */
    private static @NotNull File getTokenFile(@NotNull final String tokenFileName, @NotNull final BundleContext bundleContext) {
        File tokenFile = new File(tokenFileName);
        if (tokenFile.isAbsolute()) {
            return tokenFile;
        }

        tokenFile = bundleContext.getDataFile(tokenFileName);
        if (tokenFile == null) {
            final String slingHome = bundleContext.getProperty("sling.home");
            if (slingHome != null) {
                tokenFile = new File(slingHome, tokenFileName);
            } else {
                tokenFile = new File(tokenFileName);
            }
        }

        return tokenFile.getAbsoluteFile();
    }

}
