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
package org.apache.sling.auth.oauth_client.spi;

import java.util.Date;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenValidator.TokenValidationResult}.
 */
class TokenValidationResultTest {

    private static final String SUBJECT = "test-subject";
    private static final String ISSUER = "https://issuer.example.com";

    @Test
    void testConstructorAndGetters() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .expirationTime(new Date(System.currentTimeMillis() + 3600000))
                .build();

        TokenValidator.TokenValidationResult result = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        assertEquals(SUBJECT, result.getSubject());
        assertEquals(claimsSet, result.getClaimsSet());
    }

    @Test
    void testGetSubject() {
        String subject = "user123";
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(subject).build();

        TokenValidator.TokenValidationResult result = new TokenValidator.TokenValidationResult(subject, claimsSet);

        assertEquals(subject, result.getSubject());
    }

    @Test
    void testGetClaimsSet() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .claim("custom_claim", "custom_value")
                .build();

        TokenValidator.TokenValidationResult result = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        assertEquals(claimsSet, result.getClaimsSet());
        assertEquals(ISSUER, result.getClaimsSet().getIssuer());
        try {
            assertEquals("custom_value", result.getClaimsSet().getStringClaim("custom_claim"));
        } catch (java.text.ParseException e) {
            fail("Should not throw ParseException");
        }
    }

    @Test
    void testWithMinimalClaims() {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().subject(SUBJECT).build();

        TokenValidator.TokenValidationResult result = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
        assertEquals(SUBJECT, result.getClaimsSet().getSubject());
    }

    @Test
    void testWithComplexClaims() {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + 3600000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(SUBJECT)
                .issuer(ISSUER)
                .audience("audience1")
                .expirationTime(expiration)
                .issueTime(now)
                .jwtID("jwt-id-123")
                .claim("email", "user@example.com")
                .claim("name", "Test User")
                .claim("groups", new String[] {"admin", "users"})
                .build();

        TokenValidator.TokenValidationResult result = new TokenValidator.TokenValidationResult(SUBJECT, claimsSet);

        assertNotNull(result);
        assertEquals(SUBJECT, result.getSubject());
        assertEquals(ISSUER, result.getClaimsSet().getIssuer());
        assertEquals(1, result.getClaimsSet().getAudience().size());
        assertEquals("audience1", result.getClaimsSet().getAudience().get(0));
        assertEquals(expiration, result.getClaimsSet().getExpirationTime());
        assertEquals(now, result.getClaimsSet().getIssueTime());
        assertEquals("jwt-id-123", result.getClaimsSet().getJWTID());
    }
}
