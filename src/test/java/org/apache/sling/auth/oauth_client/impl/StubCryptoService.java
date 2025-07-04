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
package org.apache.sling.auth.oauth_client.impl;

import java.util.Base64;

import org.apache.sling.commons.crypto.CryptoService;
import org.jetbrains.annotations.NotNull;

import static java.nio.charset.StandardCharsets.UTF_8;

class StubCryptoService implements CryptoService {

    @Override
    public @NotNull String encrypt(@NotNull String plainText) {
        return Base64.getEncoder().encodeToString(plainText.getBytes(UTF_8));
    }

    @Override
    public @NotNull String decrypt(@NotNull String cipherText) {
        return new String(Base64.getDecoder().decode(cipherText), UTF_8);
    }
}
