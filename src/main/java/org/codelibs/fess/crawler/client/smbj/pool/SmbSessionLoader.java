/*
 * Copyright 2012-2024 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.fess.crawler.client.smbj.pool;

import org.apache.commons.pool2.impl.GenericKeyedObjectPool;
import org.codelibs.fess.crawler.client.smbj.SmbSession;

public class SmbSessionLoader {

    private SmbSessionKey sessionKey;

    private GenericKeyedObjectPool<SmbSessionKey, SmbSession> sessionPool;

    private SmbSession session;

    public SmbSessionLoader(final SmbSessionKey sessionKey, final GenericKeyedObjectPool<SmbSessionKey, SmbSession> sessionPool) {
        this.sessionKey = sessionKey;
        this.sessionPool = sessionPool;
    }

    public SmbSessionLoader(final SmbSession session) {
        this.session = session;
    }

    public SmbSession borrowObject() throws Exception {
        if (session != null) {
            return session;
        }
        return sessionPool.borrowObject(sessionKey);
    }

    public void returnObject(final SmbSession session) {
        if (session == null) {
            sessionPool.returnObject(sessionKey, session);
        }
    }

}
