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

import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentity;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityException;
import org.apache.jackrabbit.oak.spi.security.authentication.token.TokenConstants;
import org.apache.sling.auth.oauth_client.impl.OidcIdentityProvider.OidcGroupRef;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.junit.jupiter.api.Test;

import javax.jcr.Credentials;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class OidcIdentityProviderTest {

    @Test
    void getCredentialClasses() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        assertEquals(OidcAuthCredentials.class, test.getCredentialClasses().toArray()[0]);
    }

    @Test
    void getValidUserId() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        Credentials credentials = new OidcAuthCredentials("userId", "test");
        assertEquals("userId", test.getUserId(credentials));
    }

    @Test
    void getInvalidUserId() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        Credentials credentials = new OidcAuthCredentials("userId", "myIdp");
        assertNull(test.getUserId(credentials));
    }

    @Test
    void getAttributesValidCredentials() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        Credentials credentials = new OidcAuthCredentials("userId", "test");
        Map<String, ?> attributes = test.getAttributes(credentials);
        assertEquals(1, attributes.size());
        assertEquals("", attributes.get(TokenConstants.TOKEN_ATTRIBUTE));
    }

    @Test
    void getAttributesInvalidCredentials() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        Credentials credentials = new OidcAuthCredentials("userId", "myIdp");
        Map<String, ?> attributes = test.getAttributes(credentials);
        assertEquals(0, attributes.size());
    }

    @Test
    void setAttributesValidCredentials() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        Credentials credentials = new OidcAuthCredentials("userId", "test");

        HashMap<String, String> map = new HashMap<>();
        map.put("a", "b");
        map.put("c", "d");

        assertTrue(test.setAttributes(credentials, map));
        assertEquals("b", ((OidcAuthCredentials) credentials).getAttribute("a"));
    }

    @Test
    void setAttributesInvalidCredentials() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        Credentials credentials = new OidcAuthCredentials("userId", "myIdp");

        HashMap<String, String> map = new HashMap<>();
        map.put("a", "b");
        map.put("c", "d");

        assertFalse(test.setAttributes(credentials, map));
    }

    @Test
    void getName() {
        OidcIdentityProvider test = new OidcIdentityProvider("test");
        assertEquals("test", test.getName());
    }

    @Test
    void getIdentityValidIdp() throws ExternalIdentityException {
        OidcGroupRef groupRef = mock(OidcGroupRef.class);
        when(groupRef.getProviderName()).thenReturn("test");

        OidcIdentityProvider test = new OidcIdentityProvider("test");
        ExternalIdentity externalIdentity = test.getIdentity(groupRef);
        assertEquals(Collections.emptyList(), externalIdentity.getDeclaredGroups());
        assertEquals(Collections.emptyMap(), externalIdentity.getProperties());
    }

    @Test
    void getIdentityInvalidIdp() throws ExternalIdentityException {
        OidcGroupRef groupRef = mock(OidcGroupRef.class);
        when(groupRef.getProviderName()).thenReturn("test");

        OidcIdentityProvider test = new OidcIdentityProvider("myIdp");
        assertNull(test.getIdentity(groupRef));
    }

    @Test
    void getUser() {
    }

    @Test
    void authenticate() {
    }

    @Test
    void getGroup() {
    }

    @Test
    void listUsers() {
    }

    @Test
    void listGroups() {
    }

    @Test
    void fromExternalIdentityRef() {
    }
}