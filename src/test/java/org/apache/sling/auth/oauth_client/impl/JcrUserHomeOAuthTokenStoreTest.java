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

import static org.assertj.core.api.Assertions.assertThat;

import javax.jcr.RepositoryException;

import org.apache.jackrabbit.api.security.user.User;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ValueMap;
import org.apache.sling.auth.oauth_client.ClientConnection;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;

import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

class JcrUserHomeOAuthTokenStoreTest extends TokenStoreTestSupport<JcrUserHomeOAuthTokenStore> {
    
    JcrUserHomeOAuthTokenStoreTest() {
        super(MockOidcConnection.DEFAULT_CONNECTION, new SlingContext(ResourceResolverType.JCR_OAK));
    }

    @Override
    JcrUserHomeOAuthTokenStore createTokenStore() {
        return new JcrUserHomeOAuthTokenStore();
    }
    
    @Override
    protected void getAccessToken_valid_postCheck(OIDCTokens input) throws RepositoryException {
        Resource connectionResource = getConnectionResource(connection);

        ValueMap connectionProps = connectionResource.getValueMap();
        assertThat(connectionProps)
            .as("stored tokens for connection")
            .containsOnlyKeys("jcr:primaryType", "access_token")
            .containsEntry("access_token", input.getAccessToken().getValue());        
    }
    
    private Resource getConnectionResource(ClientConnection connection) throws RepositoryException {
        String userPath = context.resourceResolver().adaptTo(User.class).getPath();
        Resource userHomeResource = context.resourceResolver().getResource(userPath);
        Resource oidcTokensResource = userHomeResource.getChild("oauth-tokens");

        assertThat(oidcTokensResource)
            .describedAs("oauth-tokens resource")
            .isNotNull();

        Resource connectionResource = oidcTokensResource.getChild(connection.name());
        assertThat(connectionResource)
            .as("oauth-tokens/connection resource")
            .isNotNull();
        return connectionResource;
    }
}
