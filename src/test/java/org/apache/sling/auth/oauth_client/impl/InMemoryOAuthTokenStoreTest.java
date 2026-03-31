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

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;
import org.apache.sling.auth.oauth_client.InMemoryOAuthTokenStore;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.testcontainers.junit.jupiter.Testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

@Testcontainers
class InMemoryOAuthTokenStoreTest extends TokenStoreTestSupport<InMemoryOAuthTokenStore> {

    InMemoryOAuthTokenStoreTest() {
        super(MockOidcConnection.DEFAULT_CONNECTION, new SlingContext(ResourceResolverType.JCR_MOCK));
    }

    @Override
    @NotNull
    InMemoryOAuthTokenStore createTokenStore() {
        return new InMemoryOAuthTokenStore();
    }

    @Test
    void getIdToken_missing() {
        assertThat(createTokenStore().getIdToken(connection, context.resourceResolver()))
                .isNull();
    }

    @Test
    void getIdToken_persisted() {
        OIDCTokens tokens = new OIDCTokens("eyJ.id.token", new BearerAccessToken(12), null);
        InMemoryOAuthTokenStore store = createTokenStore();
        store.persistTokens(connection, context.resourceResolver(), Converter.toSlingOAuthTokens(tokens));
        assertThat(store.getIdToken(connection, context.resourceResolver())).isEqualTo("eyJ.id.token");
    }

    @Test
    void getIdToken_notStoredWhenNull() {
        OIDCTokens tokens = new OIDCTokens(new BearerAccessToken(12), null);
        InMemoryOAuthTokenStore store = createTokenStore();
        store.persistTokens(connection, context.resourceResolver(), Converter.toSlingOAuthTokens(tokens));
        assertThat(store.getIdToken(connection, context.resourceResolver())).isNull();
    }
}
