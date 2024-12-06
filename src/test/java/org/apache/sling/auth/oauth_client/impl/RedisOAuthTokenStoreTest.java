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

import java.util.Map;

import org.apache.sling.auth.oauth_client.impl.RedisOAuthTokenStore.Config;
import org.apache.sling.testing.mock.sling.ResourceResolverType;
import org.apache.sling.testing.mock.sling.junit5.SlingContext;
import org.osgi.util.converter.Converters;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import com.redis.testcontainers.RedisContainer;

@Testcontainers
public class RedisOAuthTokenStoreTest extends TokenStoreTestSupport<RedisOAuthTokenStore> {

    @Container
    private RedisContainer redis = new RedisContainer(DockerImageName.parse("redis:6.2.6"));
    
    RedisOAuthTokenStoreTest() {
        super(MockOidcConnection.DEFAULT_CONNECTION, new SlingContext(ResourceResolverType.JCR_MOCK));
    }

    @Override
    RedisOAuthTokenStore createTokenStore() {
        Config cfg = Converters.standardConverter()
            .convert(Map.of("redisUrl", redis.getRedisURI()))
            .to(RedisOAuthTokenStore.Config.class);
        
        return new RedisOAuthTokenStore(cfg);
    }
}
