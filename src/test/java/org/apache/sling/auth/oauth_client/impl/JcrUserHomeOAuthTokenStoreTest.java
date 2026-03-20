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

    private static final String TEST_USER_ID = "testUser";

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
        String plainToken = "my-id-token";
        String encryptedToken = cryptoService.encrypt(plainToken);
        Value value = mock(Value.class);
        when(user.hasProperty(connectionPath)).thenReturn(true);
        when(user.getProperty(connectionPath)).thenReturn(new Value[] {value});
        when(value.getString()).thenReturn(encryptedToken);

        String result = tokenStore.getIdToken(connection, mockResolver);

        assertEquals(plainToken, result, "Should return decrypted id_token from connection path");
    }

    @Test
    void getIdToken_foundAtProfilePath() throws RepositoryException {
        String plainToken = "profile-id-token";
        String encryptedToken = cryptoService.encrypt(plainToken);
        Value value = mock(Value.class);
        when(user.hasProperty(connectionPath)).thenReturn(false);
        when(user.hasProperty(OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN))
                .thenReturn(true);
        when(user.getProperty(OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN))
                .thenReturn(new Value[] {value});
        when(value.getString()).thenReturn(encryptedToken);

        String result = tokenStore.getIdToken(connection, mockResolver);

        assertEquals(plainToken, result, "Should return decrypted id_token from profile path");
    }

    @Test
    void getIdToken_foundAtBarePath() throws RepositoryException {
        String plainToken = "bare-id-token";
        String encryptedToken = cryptoService.encrypt(plainToken);
        Value value = mock(Value.class);
        when(user.hasProperty(connectionPath)).thenReturn(false);
        when(user.hasProperty(OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN))
                .thenReturn(false);
        when(user.hasProperty("id_token")).thenReturn(true);
        when(user.getProperty("id_token")).thenReturn(new Value[] {value});
        when(value.getString()).thenReturn(encryptedToken);

        String result = tokenStore.getIdToken(connection, mockResolver);

        assertEquals(plainToken, result, "Should return decrypted id_token from bare path");
    }

    @Test
    void getIdToken_noTokenAtAnyPath() throws RepositoryException {
        when(user.hasProperty(connectionPath)).thenReturn(false);
        when(user.hasProperty(OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN))
                .thenReturn(false);
        when(user.hasProperty("id_token")).thenReturn(false);

        String result = tokenStore.getIdToken(connection, mockResolver);

        assertNull(result, "Should return null when no id_token found at any path");
    }

    @Test
    void getIdToken_emptyValuesArray() throws RepositoryException {
        when(user.hasProperty(connectionPath)).thenReturn(true);
        when(user.getProperty(connectionPath)).thenReturn(new Value[0]);
        when(user.hasProperty(OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN))
                .thenReturn(false);
        when(user.hasProperty("id_token")).thenReturn(false);

        String result = tokenStore.getIdToken(connection, mockResolver);

        assertNull(result, "Should return null when property values array is empty");
    }

    @Test
    void getIdToken_emptyTokenValue() throws RepositoryException {
        Value value = mock(Value.class);
        when(user.hasProperty(connectionPath)).thenReturn(true);
        when(user.getProperty(connectionPath)).thenReturn(new Value[] {value});
        when(value.getString()).thenReturn("");
        when(user.hasProperty(OAuthTokenStore.PROFILE_PREFIX + OAuthTokenStore.PROPERTY_NAME_ID_TOKEN))
                .thenReturn(false);
        when(user.hasProperty("id_token")).thenReturn(false);

        String result = tokenStore.getIdToken(connection, mockResolver);

        assertNull(result, "Should return null when token value is empty string");
    }

    @Test
    void getIdToken_decryptionFails() throws RepositoryException {
        CryptoService failingCrypto = mock(CryptoService.class);
        when(failingCrypto.decrypt("bad-encrypted")).thenThrow(new RuntimeException("Decryption failed"));
        Value value = mock(Value.class);
        when(user.hasProperty(connectionPath)).thenReturn(true);
        when(user.getProperty(connectionPath)).thenReturn(new Value[] {value});
        when(value.getString()).thenReturn("bad-encrypted");

        JcrUserHomeOAuthTokenStore failingTokenStore = new JcrUserHomeOAuthTokenStore(failingCrypto);
        String result = failingTokenStore.getIdToken(connection, mockResolver);

        assertNull(result, "Should return null when decryption fails");
    }

    @Test
    void getIdToken_repositoryException() throws RepositoryException {
        when(user.hasProperty(connectionPath)).thenThrow(new RepositoryException("Test repository error"));

        assertThrows(
                OAuthException.class,
                () -> tokenStore.getIdToken(connection, mockResolver),
                "Should throw OAuthException on RepositoryException");
    }
}
