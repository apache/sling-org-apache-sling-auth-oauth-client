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

import javax.jcr.RepositoryException;
import javax.jcr.Value;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ValueMap;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JcrUserHomeOAuthTokenStoreTest extends TokenStoreTestSupport<JcrUserHomeOAuthTokenStore> {

    private CryptoService cryptoService;
    private JcrUserHomeOAuthTokenStore tokenStore;
    private User user;
    private ResourceResolver mockResolver;
    private String connectionPath;

    @BeforeEach
    void init() {
        cryptoService = new StubCryptoService();
        tokenStore = createTokenStore();
        connectionPath = "oauth-tokens/" + connection.name() + "/id_token";

        user = mock(User.class);
        mockResolver = mock(ResourceResolver.class);
        when(mockResolver.adaptTo(User.class)).thenReturn(user);
    }

    private Value encryptedValue(String plainToken) throws RepositoryException {
        Value value = mock(Value.class);
        when(value.getString()).thenReturn(cryptoService.encrypt(plainToken));
        return value;
    }

    private void givenTokenAt(String path, String plainToken) throws RepositoryException {
        Value value = encryptedValue(plainToken); // must be computed before entering outer when()
        when(user.hasProperty(path)).thenReturn(true);
        when(user.getProperty(path)).thenReturn(new Value[] {value});
    }

    JcrUserHomeOAuthTokenStoreTest() {
        super(MockOidcConnection.DEFAULT_CONNECTION, new SlingContext(ResourceResolverType.JCR_OAK));
    }

    @Override
    JcrUserHomeOAuthTokenStore createTokenStore() {
        return new JcrUserHomeOAuthTokenStore(cryptoService);
    }

    @Override
    protected void getAccessToken_valid_postCheck(OIDCTokens input) throws RepositoryException {

        // validate that encryption is applied when storing the access token

        Resource connectionResource = getConnectionResource(connection);

        ValueMap connectionProps = connectionResource.getValueMap();
        assertThat(connectionProps)
                .as("stored tokens for connection")
                .containsOnlyKeys("jcr:primaryType", "access_token");

        assertThat(connectionProps.get("access_token", String.class))
                .as("encrypted access token")
                .isNotEqualTo(input.getAccessToken().getValue())
                .isEqualTo(cryptoService.encrypt(input.getAccessToken().getValue()));
    }

    private Resource getConnectionResource(ClientConnection connection) throws RepositoryException {
        String userPath = context.resourceResolver().adaptTo(User.class).getPath();
        Resource userHomeResource = context.resourceResolver().getResource(userPath);
        Resource oidcTokensResource = userHomeResource.getChild("oauth-tokens");

        assertThat(oidcTokensResource).describedAs("oauth-tokens resource").isNotNull();

        Resource connectionResource = oidcTokensResource.getChild(connection.name());
        assertThat(connectionResource).as("oauth-tokens/connection resource").isNotNull();
        return connectionResource;
    }

    // ========== Tests for getIdToken method ==========

    @Test
    void getIdToken_foundAtConnectionPath() throws RepositoryException {
        givenTokenAt(connectionPath, "my-id-token");
        assertEquals("my-id-token", tokenStore.getIdToken(connection, mockResolver));
    }

    @Test
    void getIdToken_foundAtProfilePath() throws RepositoryException {
        givenTokenAt(OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN, "profile-id-token");
        assertEquals("profile-id-token", tokenStore.getIdToken(connection, mockResolver));
    }

    @Test
    void getIdToken_foundAtBarePath() throws RepositoryException {
        givenTokenAt("id_token", "bare-id-token");
        assertEquals("bare-id-token", tokenStore.getIdToken(connection, mockResolver));
    }

    @Test
    void getIdToken_noTokenAtAnyPath() {
        assertNull(tokenStore.getIdToken(connection, mockResolver));
    }

    @Test
    void getIdToken_emptyOrMissingValue() throws RepositoryException {
        // empty array
        when(user.hasProperty(connectionPath)).thenReturn(true);
        when(user.getProperty(connectionPath)).thenReturn(new Value[0]);
        assertNull(tokenStore.getIdToken(connection, mockResolver));

        // empty string value
        Value emptyValue = mock(Value.class);
        when(emptyValue.getString()).thenReturn("");
        when(user.getProperty(connectionPath)).thenReturn(new Value[] {emptyValue});
        assertNull(tokenStore.getIdToken(connection, mockResolver));
    }

    @Test
    void getIdToken_decryptionFails() throws RepositoryException {
        CryptoService failingCrypto = mock(CryptoService.class);
        when(failingCrypto.decrypt("bad")).thenThrow(new RuntimeException("fail"));
        Value value = mock(Value.class);
        when(value.getString()).thenReturn("bad");
        when(user.hasProperty(connectionPath)).thenReturn(true);
        when(user.getProperty(connectionPath)).thenReturn(new Value[] {value});
        assertNull(new JcrUserHomeOAuthTokenStore(failingCrypto).getIdToken(connection, mockResolver));
    }

    @Test
    void getIdToken_repositoryException() throws RepositoryException {
        when(user.hasProperty(connectionPath)).thenThrow(new RepositoryException());
        assertThrows(OAuthException.class, () -> tokenStore.getIdToken(connection, mockResolver));
    }
}
