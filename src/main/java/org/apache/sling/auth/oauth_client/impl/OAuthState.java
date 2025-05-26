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

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class OAuthState {

    private final @NotNull String perRequestKey;
    private final @NotNull String connectionName;
    private final @Nullable String redirect;

    public OAuthState(@NotNull String perRequestKey, @NotNull String connectionName, @Nullable String redirect) {
        this.perRequestKey = perRequestKey;
        this.connectionName = connectionName;
        this.redirect = redirect;
    }

    public @NotNull String perRequestKey() {
        return perRequestKey;
    }

    public @NotNull String connectionName() {
        return connectionName;
    }

    public @Nullable String redirect() {
        return redirect;
    }

    //implement equals and hashCode
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof OAuthState)) return false;

        OAuthState that = (OAuthState) o;

        if (!perRequestKey.equals(that.perRequestKey)) return false;
        if (!connectionName.equals(that.connectionName)) return false;
        return (redirect != null ? redirect.equals(that.redirect) : that.redirect == null);
    }

    @Override
    public int hashCode() {
        int result = perRequestKey.hashCode();
        result = 31 * result + connectionName.hashCode();
        result = 31 * result + (redirect != null ? redirect.hashCode() : 0);
        return result;
    }
}