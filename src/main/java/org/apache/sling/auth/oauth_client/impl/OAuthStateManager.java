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

import java.util.Optional;

import com.nimbusds.oauth2.sdk.id.State;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public interface OAuthStateManager {
    
    String PARAMETER_NAME_REDIRECT = "redirect";
    String COOKIE_NAME_REQUEST_KEY = "sling.oauth-request-key";

    @NotNull State toNimbusState(@NotNull OAuthCookieValue state);
    
    @NotNull Optional<OAuthCookieValue> toOAuthState(@Nullable State state);

}
