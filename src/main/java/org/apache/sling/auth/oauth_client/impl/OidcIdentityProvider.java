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

import org.apache.jackrabbit.oak.spi.security.authentication.credentials.CredentialsSupport;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalGroup;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentity;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityException;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityProvider;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalIdentityRef;
import org.apache.jackrabbit.oak.spi.security.authentication.external.ExternalUser;
import org.apache.jackrabbit.oak.spi.security.authentication.external.PrincipalNameResolver;
import org.apache.jackrabbit.oak.spi.security.authentication.token.TokenConstants;
import org.apache.sling.auth.oauth_client.spi.OidcAuthCredentials;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.jcr.Credentials;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

class OidcIdentityProvider implements ExternalIdentityProvider, PrincipalNameResolver, CredentialsSupport  {

    private final String name;
    
    OidcIdentityProvider(@NotNull String name) {
        this.name=name;
    }

    @Override
    public @NotNull Set<Class> getCredentialClasses() {
        return Collections.singleton(OidcAuthCredentials.class);
    }

    @Override
    public @Nullable String getUserId(@NotNull Credentials credentials) {
        if (validCredentials(credentials)) {
            return ((OidcAuthCredentials) credentials).getUserId();
        }
        return null;
    }

    //Must return attributes to be set to the Token, but NOT profile information
    @Override
    public @NotNull Map<String, ?> getAttributes(@NotNull Credentials credentials) {
        if (validCredentials(credentials)) {
            return Collections.singletonMap(TokenConstants.TOKEN_ATTRIBUTE, "");
        }
        return Collections.emptyMap();
    }

    @Override
    public boolean setAttributes(@NotNull Credentials credentials, @NotNull Map<String, ?> map) {
        if (validCredentials(credentials)) {
            OidcAuthCredentials oidcAuthCredentials = (OidcAuthCredentials)credentials;
            map.keySet().forEach(key -> oidcAuthCredentials.setAttribute(key, (String) map.get(key)));
            return true;
        }
        return false;
    }

    @Override
    public @NotNull String getName() {
        return name;
    }

    @Override
    public @Nullable ExternalIdentity getIdentity(@NotNull ExternalIdentityRef externalIdentityRef) {
        if (isSameIdp(externalIdentityRef) && externalIdentityRef instanceof OidcGroupRef) {
            return new OidcGroup(externalIdentityRef);
        } 
        return null;
    }

    @Override
    public @Nullable ExternalUser getUser(@NotNull String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public @Nullable ExternalUser authenticate(@NotNull Credentials credentials) {
        if (validCredentials(credentials)) {
            return new OidcUser((OidcAuthCredentials) credentials);
        }
        return null;
    }
    
    @Override
    public @Nullable ExternalGroup getGroup(@NotNull String s) {
        throw new UnsupportedOperationException();
    }

    @Override
    public @NotNull Iterator<ExternalUser> listUsers() {
        throw new UnsupportedOperationException();
    }

    @Override
    public @NotNull Iterator<ExternalGroup> listGroups() {
        throw new UnsupportedOperationException();
    }

    @Override
    public @NotNull String fromExternalIdentityRef(@NotNull ExternalIdentityRef externalIdentityRef) throws ExternalIdentityException {
        if (!isSameIdp(externalIdentityRef)) {
            throw new ExternalIdentityException("Foreign IDP " + externalIdentityRef.getString());
        }
        return externalIdentityRef.getId();
    }
    
    private boolean validCredentials(@NotNull Credentials credentials) {
        return credentials instanceof OidcAuthCredentials && isSameIdp((OidcAuthCredentials) credentials);
    }
    
    private boolean isSameIdp(@NotNull OidcAuthCredentials credentials) {
        return name.equals(credentials.getIdp());
    }
    
    private boolean isSameIdp(@NotNull ExternalIdentityRef ref) {
        return name.equals(ref.getProviderName());
    }
    
    private abstract static class OidcIdentity implements ExternalIdentity {

        private final ExternalIdentityRef ref;
        
        private OidcIdentity(@NotNull ExternalIdentityRef ref) {
            this.ref = ref;
        }
        
        @Override
        public @NotNull ExternalIdentityRef getExternalId() {
            return ref;
        }

        @Override
        public @NotNull String getId() {
            return ref.getId();
        }

        @Override
        public @NotNull String getPrincipalName() {
            return getId();
        }

        @Override
        public @Nullable String getIntermediatePath() {
            return "";
        }
    }
    
    private final  class OidcUser extends OidcIdentity implements ExternalUser {

        private final OidcAuthCredentials creds;
        private final Iterable<String> groups;

        private OidcUser(@NotNull OidcAuthCredentials creds) {
            super(new ExternalIdentityRef(creds.getUserId(), creds.getIdp()));

            this.creds = creds;
            this.groups = creds.getGroups();
        }

        @Override
        public @NotNull Iterable<ExternalIdentityRef> getDeclaredGroups() {
            List<ExternalIdentityRef> externalGroups = new ArrayList<>();
            groups.forEach(group -> externalGroups.add(new OidcGroupRef(group, creds.getIdp())));
            return externalGroups;
        }

        @Override
        public @NotNull Map<String, ?> getProperties() {
            return creds.getAttributes();
        }

        @Override
        public ExternalIdentityRef getExternalId() {
            return new ExternalIdentityRef(creds.getUserId(), creds.getIdp());
        }
    }
    private final  class OidcGroup extends OidcIdentity implements ExternalGroup {

        private OidcGroup(@NotNull ExternalIdentityRef ref) {
            super(ref);
        }
        
        @Override
        public @NotNull Iterable<ExternalIdentityRef> getDeclaredGroups() {
            return Collections.emptyList();
        }

        @Override
        public @NotNull Map<String, ?> getProperties() {
            return Collections.emptyMap();
        }

        @Override
        public @NotNull Iterable<ExternalIdentityRef> getDeclaredMembers() {
            return Collections.emptyList();
        }
    }
    
    private  class OidcGroupRef extends ExternalIdentityRef {
        OidcGroupRef(@NotNull String id, @NotNull String idp) {
            super(id, idp);
        }
    }

}
