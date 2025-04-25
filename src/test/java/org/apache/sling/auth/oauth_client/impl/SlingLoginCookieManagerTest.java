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

import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.jcr.resource.api.JcrResourceConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.osgi.framework.BundleContext;

import javax.servlet.http.Cookie;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SlingLoginCookieManagerTest {

    private MockRequest request = new MockRequest();
    private MockResponse response = new MockResponse();
    private SlingRepository repository = mock(SlingRepository.class);
    private SlingLoginCookieManager slingLoginCookieManager;

    @BeforeEach
    void setup() throws IOException, NoSuchAlgorithmException, InvalidKeyException {
        SlingLoginCookieManager.SlingLoginCookieManagerConfig config = mock(SlingLoginCookieManager.SlingLoginCookieManagerConfig.class);

        Path tempFilePath = Files.createTempFile("cookie-tokens","bin");
        File tempFile = tempFilePath.toFile();

        when(config.tokenFile()).thenReturn(tempFile.getName());
        when(config.form_token_fastseed()).thenReturn(false);
        when(config.sessionTimeout()).thenReturn(8 * 60 * 60 * 1000l);
        when(config.cookieName()).thenReturn("sling.oidcauth");

        BundleContext bundleContext = mock(BundleContext.class);
        when(bundleContext.getDataFile("cookie-tokens")).thenReturn(tempFile);
        
        slingLoginCookieManager = new SlingLoginCookieManager(config, bundleContext);
    }
    
    @Test
    void setGetVerifyLoginCookie() {
        OidcAuthCredentials creds = mock(OidcAuthCredentials.class);
        when(creds.getUserId()).thenReturn("testUser");

        slingLoginCookieManager.setLoginCookie(request, response, repository, creds);

        Cookie cookie = parseSetCookieHeader(response.getHeader("Set-Cookie"));
        assertNotNull(cookie);

        assertEquals("sling.oidcauth", cookie.getName());
        assertTrue(new String (Base64.getDecoder().decode(cookie.getValue())).endsWith("testUser"));

        request.addCookie(cookie);
        assertEquals(cookie, slingLoginCookieManager.getLoginCookie(request));

        AuthenticationInfo authInfo = slingLoginCookieManager.verifyLoginCookie(request);
        assertTrue(authInfo.get(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS) instanceof OidcAuthCredentials);
        assertEquals("testUser",  authInfo.getUser());

    }

    @Test
    void verifyNoLoginCookie() {
        //No cookies are set
        assertNull(slingLoginCookieManager.verifyLoginCookie(request));
    }

    @Test
    void verifyLoginCookieNoValue() {
        Cookie cookie = new Cookie("sling.oidcauth", "");
        request.addCookie(cookie);
        assertNull(slingLoginCookieManager.verifyLoginCookie(request));
    }

    @Test
    void verifyLoginCookieOtherNoLoginCookie() {
        Cookie cookie1 = new Cookie("test1", "test" );
        request.addCookie(cookie1);
        Cookie cookie2 = new Cookie("test2", "test" );
        request.addCookie(cookie2);

        assertNull(slingLoginCookieManager.verifyLoginCookie(request));
    }


    @Test
    void verifyLoginCookieInvalidValue() {
        Cookie cookie = new Cookie("sling.oidcauth", Base64.getEncoder().encodeToString("invalidValue".getBytes()) );
        request.addCookie(cookie);
        assertNull(slingLoginCookieManager.verifyLoginCookie(request));
    }


    @Test
    void getLoginCookie() {
    }

    @Test
    void getUserId() {
    }

    @Test
    void getTokenFile() {
    }

    static Cookie parseSetCookieHeader(String setCookieHeader) {
        // Split the header into parts
        String[] parts = setCookieHeader.split(";");
        String[] nameValue = parts[0].split("=", 2);

        // Create the Cookie object
        Cookie cookie = new Cookie(nameValue[0].trim(), nameValue[1].trim());

        // Parse additional attributes (optional)
        for (int i = 1; i < parts.length; i++) {
            String part = parts[i].trim().toLowerCase();
            if (part.startsWith("path=")) {
                cookie.setPath(part.substring(5));
            } else if (part.startsWith("domain=")) {
                cookie.setDomain(part.substring(7));
            } else if (part.equals("secure")) {
                cookie.setSecure(true);
            } else if (part.equals("httponly")) {
                cookie.setHttpOnly(true);
            }
        }

        return cookie;
    }

}