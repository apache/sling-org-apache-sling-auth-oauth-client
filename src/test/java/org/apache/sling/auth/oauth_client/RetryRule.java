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

import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

//Credits to: https://www.swtestacademy.com/rerun-failed-test-junit/
public class RetryRule implements TestRule {

    Logger log = LoggerFactory.getLogger(RetryRule.class);
    private int retryCount;
    public RetryRule(int retryCount) {
        this.retryCount = retryCount;
    }
    public Statement apply(Statement base, Description description) {
        return statement(base, description);
    }
    private Statement statement(final Statement base, final Description description) {
        return new Statement() {
            @Override
            public void evaluate() throws Throwable {
                Throwable caughtThrowable = null;
                for (int i = 0; i < retryCount; i++) {
                    try {
                        base.evaluate();
                        return;
                    }
                    catch (Throwable t) {
                        caughtThrowable = t;
                        log.error(description.getDisplayName() + ": run " + (i + 1) + " failed.");
                    }
                }
                log.error(description.getDisplayName() + ": Giving up after " + retryCount + " failures.");
                throw Objects.requireNonNull(caughtThrowable);
            }
        };
    }
}
