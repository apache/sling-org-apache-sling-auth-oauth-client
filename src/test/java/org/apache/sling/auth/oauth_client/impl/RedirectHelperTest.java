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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RedirectHelperTest {

    @Test
    void testFindLongestPathMatchingWithValidPaths() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "http://example.com/a/b/c/d";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a/b/c", result);
    }

    @Test
    void testFindLongestPathMatchingWithNoMatchingPath() {
        String[] paths = {"/x/y", "/z"};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithEmptyPaths() {
        String[] paths = {};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithNullUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String result = RedirectHelper.findLongestPathMatching(paths, null);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithEmptyUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String result = RedirectHelper.findLongestPathMatching(paths, "");
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithSinglePath() {
        String[] paths = {"/a"};
        String url = "http://example.com/a/b/c";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a", result);
    }

    @Test
    void testFindLongestPathMatchingWithInvalidUrl() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "invalid-url";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertNull(result);
    }

    @Test
    void testFindLongestPathMatchingWithSibling() {
        String[] paths = {"/a/b/c", "/a/b", "/a"};
        String url = "http://example.com/a/b/c_sibling/d";
        String result = RedirectHelper.findLongestPathMatching(paths, url);
        assertEquals("/a/b", result);
    }
}