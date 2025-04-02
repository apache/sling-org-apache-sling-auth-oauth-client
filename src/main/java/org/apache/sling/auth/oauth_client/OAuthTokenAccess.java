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
package org.apache.sling.auth.oauth_client;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.oauth_client.impl.OAuthTokenStore;
import org.jetbrains.annotations.NotNull;

/**
 * Entry point for accessing and clearing OAuth access tokens
 * 
 * <p>The tokens are stored distinctly for each client connection and user. The client connection is identified by 
 * {@link ClientConnection#name() name} and the user is identified by the {@link ResourceResolver#getUserID() user id}. </p>
 * 
 * <p>The storage strategy may vary and is controlled by the currently active implementation of the {@link OAuthTokenStore}.</p>
 */
@NotNull
public interface OAuthTokenAccess {

    /**
     * Retrieves an existing access, valid, access token from storage.
     * 
     * <p>Refreshes expired access tokens if a refresh token is available but does not attempt to retrieve new access tokens.</p>
     * 
     * @param connection the client connection to retrieve token for
     * @param request the request used to determine the current user for which to retrieve the token and to build the redirect URL
     * @param redirectPath the path to redirect to after completing the OAuth flow
     * @return the token response
     */
    OAuthTokenResponse getAccessToken(ClientConnection connection, SlingHttpServletRequest request, String redirectPath);

    /**
     * Clears the access token for the given connection and user, as identified by the request.
     * 
     * <p>Returns a response that does not have a valid token and contains a URI to redirect the user to.</p>
     * 
     * @param connection the client connection to clear the token for
     * @param request the request used to determine the current user for which to retrieve the token and to build the redirect URL
     * @param redirectPath the path to redirect to after completing the OAuth flow 
     * @return the token response
     */
    OAuthTokenResponse clearAccessToken(ClientConnection connection, SlingHttpServletRequest request, String redirectPath);

    /**
     * Clears the access token for the given connection and user, as identified by the resource resolver
     * 
     * <p>For scenarios where a redirect URI should be generated after clearing the access token {@link #clearAccessToken(ClientConnection, SlingHttpServletRequest, String)}
     * should be used instead.</p>
     * 
     * @param connection the client connection to clear the token for
     * @param resolver used to determine the current user for which to retrieve the token
     */
    void clearAccessToken(ClientConnection connection, ResourceResolver resolver);

}