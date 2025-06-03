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

import javax.jcr.Credentials;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.jcr.api.SlingRepository;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * This class is responsible for managing authentication cookie.
 */
public interface LoginCookieManager {

    /**
     * Set the login cookie in the response after a successful authentication.
     * @param request
     * @param response
     * @param repository
     * @param creds
     */
    void setLoginCookie(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull SlingRepository repository,
            @NotNull Credentials creds);

    /**
     * Verify the login cookie in the request. If the Authentication Handler do not verify the cookie, return null.
     * @param request
     * @return AuthenticationInfo
     */
    @Nullable
    AuthenticationInfo verifyLoginCookie(@NotNull HttpServletRequest request);

    /**
     * Get the login cookie from the request. If the Authentication Handler do not verify the cookie, return null.
     * @param request
     * @return Cookie
     */
    @Nullable
    Cookie getLoginCookie(@NotNull HttpServletRequest request);
}
