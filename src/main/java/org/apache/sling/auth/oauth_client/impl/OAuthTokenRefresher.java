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

import org.apache.sling.auth.oauth_client.ClientConnection;

public interface OAuthTokenRefresher {

    /**
     * Refreshes the OAuth tokens based on the supplied refresh token
     * 
     * <p>It is the responsibility of the invoker to persist the returned tokens.</p> 
     * 
     * @param connection The connection to refresh the tokens for
     * @param refreshToken An existing refresh token
     * @return OAuth tokens
     * @throws OAuthException in case anything goes wrong
     */
    OAuthTokens refreshTokens(ClientConnection connection, String refreshToken) throws OAuthException;
}