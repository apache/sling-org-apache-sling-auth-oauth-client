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

import javax.servlet.AsyncContext;
import javax.servlet.DispatcherType;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpUpgradeHandler;
import javax.servlet.http.Part;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public class MockRequest implements HttpServletRequest {

    ArrayList<Cookie> cookies;
    HashMap<String, Object> attributes = new HashMap<>();
    @Override
    public String getAuthType() {
        // TODO
        return null;
    }

    @Override
    public Cookie[] getCookies() {
        if (cookies == null) {
            return null;
        }
        return cookies.toArray(new Cookie[cookies.size()]);
    }

    public void addCookie(Cookie cookie) {
        if (cookies == null) {
            cookies = new ArrayList<Cookie>();
        }
        cookies.add(cookie);
    }

    @Override
    public long getDateHeader(String name) {
        // TODO
        return 0;
    }

    @Override
    public String getHeader(String name) {
        // TODO
        return null;
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        // TODO
        return null;
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        // TODO
        return null;
    }

    @Override
    public int getIntHeader(String name) {
        // TODO
        return 0;
    }

    @Override
    public String getMethod() {
        // TODO
        return null;
    }

    @Override
    public String getPathInfo() {
        // TODO
        return null;
    }

    @Override
    public String getPathTranslated() {
        // TODO
        return null;
    }

    @Override
    public String getContextPath() {
        // TODO
        return null;
    }

    @Override
    public String getQueryString() {
        // TODO
        return null;
    }

    @Override
    public String getRemoteUser() {
        // TODO
        return null;
    }

    @Override
    public boolean isUserInRole(String role) {
        // TODO
        return false;
    }

    @Override
    public Principal getUserPrincipal() {
        // TODO
        return null;
    }

    @Override
    public String getRequestedSessionId() {
        // TODO
        return null;
    }

    @Override
    public String getRequestURI() {
        // TODO
        return null;
    }

    @Override
    public StringBuffer getRequestURL() {
        // TODO
        return null;
    }

    @Override
    public String getServletPath() {
        // TODO
        return null;
    }

    @Override
    public HttpSession getSession(boolean create) {
        // TODO
        return null;
    }

    @Override
    public HttpSession getSession() {
        // TODO
        return null;
    }

    @Override
    public String changeSessionId() {
        // TODO
        return null;
    }

    @Override
    public boolean isRequestedSessionIdValid() {
        // TODO
        return false;
    }

    @Override
    public boolean isRequestedSessionIdFromCookie() {
        // TODO
        return false;
    }

    @Override
    public boolean isRequestedSessionIdFromURL() {
        // TODO
        return false;
    }

    @Override
    public boolean isRequestedSessionIdFromUrl() {
        // TODO
        return false;
    }

    @Override
    public boolean authenticate(HttpServletResponse response) throws IOException, ServletException {
        // TODO
        return false;
    }

    @Override
    public void login(String username, String password) throws ServletException {
        // TODO

    }

    @Override
    public void logout() throws ServletException {
        // TODO

    }

    @Override
    public Collection<Part> getParts() throws IOException, ServletException {
        // TODO
        return null;
    }

    @Override
    public Part getPart(String name) throws IOException, ServletException {
        // TODO
        return null;
    }

    @Override
    public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) throws IOException, ServletException {
        // TODO
        return null;
    }

    @Override
    public Object getAttribute(String name) {
        return attributes.get(name);
    }

    @Override
    public Enumeration<String> getAttributeNames() {
        // TODO
        return null;
    }

    @Override
    public String getCharacterEncoding() {
        // TODO
        return null;
    }

    @Override
    public void setCharacterEncoding(String env) throws UnsupportedEncodingException {
        // TODO

    }

    @Override
    public int getContentLength() {
        // TODO
        return 0;
    }

    @Override
    public long getContentLengthLong() {
        // TODO
        return 0;
    }

    @Override
    public String getContentType() {
        // TODO
        return null;
    }

    @Override
    public ServletInputStream getInputStream() throws IOException {
        // TODO
        return null;
    }

    @Override
    public String getParameter(String name) {
        // TODO
        return null;
    }

    @Override
    public Enumeration<String> getParameterNames() {
        // TODO
        return null;
    }

    @Override
    public String[] getParameterValues(String name) {
        // TODO
        return new String[0];
    }

    @Override
    public Map<String, String[]> getParameterMap() {
        // TODO
        return null;
    }

    @Override
    public String getProtocol() {
        // TODO
        return null;
    }

    @Override
    public String getScheme() {
        // TODO
        return null;
    }

    @Override
    public String getServerName() {
        // TODO
        return null;
    }

    @Override
    public int getServerPort() {
        // TODO
        return 0;
    }

    @Override
    public BufferedReader getReader() throws IOException {
        // TODO
        return null;
    }

    @Override
    public String getRemoteAddr() {
        // TODO
        return null;
    }

    @Override
    public String getRemoteHost() {
        // TODO
        return null;
    }

    @Override
    public void setAttribute(String name, Object o) {
        attributes.put(name, o);
    }

    @Override
    public void removeAttribute(String name) {
        // TODO

    }

    @Override
    public Locale getLocale() {
        // TODO
        return null;
    }

    @Override
    public Enumeration<Locale> getLocales() {
        // TODO
        return null;
    }

    @Override
    public boolean isSecure() {
        // TODO
        return false;
    }

    @Override
    public RequestDispatcher getRequestDispatcher(String path) {
        // TODO
        return null;
    }

    @Override
    public String getRealPath(String path) {
        // TODO
        return null;
    }

    @Override
    public int getRemotePort() {
        // TODO
        return 0;
    }

    @Override
    public String getLocalName() {
        // TODO
        return null;
    }

    @Override
    public String getLocalAddr() {
        // TODO
        return null;
    }

    @Override
    public int getLocalPort() {
        // TODO
        return 0;
    }

    @Override
    public ServletContext getServletContext() {
        // TODO
        return null;
    }

    @Override
    public AsyncContext startAsync() throws IllegalStateException {
        // TODO
        return null;
    }

    @Override
    public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse) throws IllegalStateException {
        // TODO
        return null;
    }

    @Override
    public boolean isAsyncStarted() {
        // TODO
        return false;
    }

    @Override
    public boolean isAsyncSupported() {
        // TODO
        return false;
    }

    @Override
    public AsyncContext getAsyncContext() {
        // TODO
        return null;
    }

    @Override
    public DispatcherType getDispatcherType() {
        // TODO
        return null;
    }
}
