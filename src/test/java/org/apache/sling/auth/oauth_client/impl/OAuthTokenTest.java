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

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class OAuthTokenTest {

    @Test
    void testValidToken() {
        OAuthToken token = new OAuthToken(TokenState.VALID, "valid_token");
        assert token.getState() == TokenState.VALID;
        assert "valid_token".equals(token.getValue());
    }

    @Test
    void testValidTokenWithoutState() {
        OAuthToken token = new OAuthToken("valid_token");
        assert token.getState() == TokenState.VALID;
        assert "valid_token".equals(token.getValue());
    }

    @Test
    void testValidTokenCannotBeNull() {
        try {
            OAuthToken token = new OAuthToken(TokenState.VALID, null);
            Assertions.fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assert "Token state is VALID but no token value is provided".equals(e.getMessage());
        }
    }

    @Test
    void testNullToken() {
        OAuthToken token = new OAuthToken(TokenState.MISSING, null);
        assert token.getState() == TokenState.MISSING;
    }
    
    @Test
    void testGetValueMissingState() {
        OAuthToken token = new OAuthToken(TokenState.MISSING, null);
        try {
            token.getValue();
            Assertions.fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            assert "Can't retrieve a token value when the token state is MISSING".equals(e.getMessage());
        }
    }

    @Test
    void testGetValueExpiredState() {
        OAuthToken token = new OAuthToken(TokenState.EXPIRED, null);
        try {
            token.getValue();
            Assertions.fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            assert "Can't retrieve a token value when the token state is EXPIRED".equals(e.getMessage());
        }
    }
}