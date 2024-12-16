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

import static java.lang.String.format;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.commons.crypto.CryptoService;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.jetbrains.annotations.NotNull;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.osgi.service.component.annotations.ReferencePolicyOption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(service = Servlet.class)
@SlingServletPaths("/system/sling/decrypt")
public class DecryptOAuthTokenServlet extends SlingAllMethodsServlet {
    
    private static final long serialVersionUID = 1L;
    
    private final Logger logger = LoggerFactory.getLogger(getClass());
    private final Map<String,CryptoService> cryptoServicesByName = new HashMap<>();
    
    @Activate
    public DecryptOAuthTokenServlet(@Reference(
            service=CryptoService.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC,
            policyOption = ReferencePolicyOption.GREEDY) 
        List<ServiceReference<CryptoService>> cryptoServices, BundleContext ctx) {
        
        cryptoServices.forEach( sr -> {
           CryptoService cs = ctx.getService(sr);
           String[] cryptoNames = (String[]) sr.getProperty("names");
            for (String cryptoName : cryptoNames)
                cryptoServicesByName.put(cryptoName, cs);
        });

        logger.info("Collected cryptoServices with names: {}", cryptoServicesByName.keySet());
    }

    @Override
    protected void doPost(@NotNull SlingHttpServletRequest request, @NotNull SlingHttpServletResponse response)
            throws ServletException, IOException {
        String token = request.getParameter("token");
        if (token == null) {
            response.sendError(400, "Missing 'token' parameter");
            return;
        }
        
        String cryptoServiceName = request.getParameter("cryptoServiceName");
        if (cryptoServiceName == null) {
            response.sendError(400, "Missing 'cryptoServiceName' parameter");
            return;
        }
        
        CryptoService cryptoService = cryptoServicesByName.get(cryptoServiceName);
        if (cryptoService == null) {
            response.sendError(400, format("Unknown cryptoService  parameter '%s'", cryptoServiceName));
            return;
        }
        
        logger.info("Decrypting token {}", token);
        
        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("text/plain");
        response.getWriter().write(cryptoService.decrypt(token));
    }

}
