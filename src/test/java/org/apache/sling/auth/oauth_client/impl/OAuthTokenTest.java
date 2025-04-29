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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class OAuthTokenTest {

    @Test
    void testValidToken() {
        OAuthToken token = new OAuthToken(TokenState.VALID, "valid_token");
        assertSame(TokenState.VALID, token.getState());
        assertEquals("valid_token", token.getValue());
    }

    @Test
    void testValidTokenWithoutState() {
        OAuthToken token = new OAuthToken("valid_token");
        assertSame(TokenState.VALID, token.getState());
        assertEquals("valid_token", token.getValue());
    }

    @Test
    void testValidTokenCannotBeNull() {
        try {
            OAuthToken token = new OAuthToken(TokenState.VALID, null);
            Assertions.fail("Expected IllegalArgumentException");
        } catch (IllegalArgumentException e) {
            assertEquals("Token state is VALID but no token value is provided", e.getMessage());
        }
    }

    @Test
    void testNullToken() {
        OAuthToken token = new OAuthToken(TokenState.MISSING, null);
        assertSame(TokenState.MISSING, token.getState());
    }
    
    @Test
    void testGetValueMissingState() {
        OAuthToken token = new OAuthToken(TokenState.MISSING, null);
        try {
            token.getValue();
            Assertions.fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            assertEquals("Can't retrieve a token value when the token state is MISSING", e.getMessage());
        }
    }

    @Test
    void testGetValueExpiredState() {
        OAuthToken token = new OAuthToken(TokenState.EXPIRED, null);
        try {
            token.getValue();
            Assertions.fail("Expected IllegalStateException");
        } catch (IllegalStateException e) {
            assertEquals("Can't retrieve a token value when the token state is EXPIRED", e.getMessage());
        }
    }
}