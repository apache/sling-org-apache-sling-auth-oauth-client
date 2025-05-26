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

import org.jetbrains.annotations.NotNull;

/**
 * Identifies an OAuth or OIDC connection
 * 
 * <p>Used in the public API to identify the client connection for which to retrieve or clear tokens.</p>
 * 
 * <p>Connections are published as OSGi services and should be retrieved using the <code>name</code> property.</p>
 * 
 * <pre>{@code private @Reference(target = "(name=my-connection-name)")} ClientConnection connection;}</pre>
 * 
 * @see OAuthTokenAccess
 */
public interface ClientConnection {

    /**
     * @return the name of the connection
     */
    @NotNull String name();
}
