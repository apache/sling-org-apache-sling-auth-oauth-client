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
package org.apache.sling.auth.oauth_client.itbundle;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.sling.testing.clients.ClientException;
import org.apache.sling.testing.clients.osgi.OsgiConsoleClient;
import org.ops4j.pax.tinybundles.TinyBundles;
import org.osgi.framework.Constants;

public class SupportBundle {
    
    public static final String BUNDLE_SYMBOLIC_NAME = "org.apache.sling.auth.oauth_client.itbundle";

    private final Path parentDirectory;
    private Path bundlePath;

    public SupportBundle(Path parentDirectory) {
        this.parentDirectory = parentDirectory;
    }

    public Path generate() throws IOException {
        
        InputStream bundleStream = TinyBundles
                .bundle()
                .setHeader(Constants.BUNDLE_SYMBOLICNAME, BUNDLE_SYMBOLIC_NAME)
                .setHeader(Constants.BUNDLE_VERSION, "1.0.0-SNAPSHOT")
                .addClass(DecryptOAuthTokenServlet.class)
                .build(TinyBundles.bndBuilder());
            
        bundlePath = parentDirectory.resolve("support-bundle.jar");
        Files.copy(bundleStream, bundlePath);
        
        return bundlePath;
    }
    
    public void install(OsgiConsoleClient client) throws ClientException, InterruptedException, TimeoutException  {

        if (bundlePath == null)
            throw new IllegalStateException("Bundle not generated");
        
        client.waitInstallBundle(bundlePath.toFile(), true, 10, TimeUnit.SECONDS.toMillis(10), 500);
    }
    
    public void uninstall(OsgiConsoleClient client) throws ClientException {
        client.uninstallBundle(BUNDLE_SYMBOLIC_NAME);
    }
    
    public void cleanup() throws IOException {
        
        if ( bundlePath == null )
            throw new IllegalStateException("Bundle not generated");
        
        Files.delete(bundlePath);
    }
    
}
