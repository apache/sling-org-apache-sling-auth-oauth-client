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

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityRef;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class OidcAuthCredentials implements Credentials {

    private final ExternalIdentityRef userId;

    private final String idp;
    private final Map<String, Object> attributes = new HashMap<>();
    private final Set<String> groups = new HashSet<>();

    public OidcAuthCredentials(@NotNull String userId, @NotNull String idp) {
        this.userId = new ExternalIdentityRef(userId, idp);
        this.idp = idp;
    }

    @NotNull
    public String getUserId() {
        return userId.getId();
    }

    @NotNull
    public String getIdp() {
        return idp;
    }

    @NotNull
    public Map<String, Object> getAttributes() {
        return Collections.unmodifiableMap(attributes);
    }

    public void setAttribute(@NotNull String key, @NotNull String value) {
        synchronized (attributes) {
            attributes.put(key, value);
        }
    }

    @Nullable
    public Object getAttribute(@NotNull String key) {
        return attributes.get(key);
    }

    public void addGroup(@NotNull String group) {
        this.groups.add(group);
    }

    @NotNull
    public Iterable<String> getGroups() {
        return groups;
    }
}
