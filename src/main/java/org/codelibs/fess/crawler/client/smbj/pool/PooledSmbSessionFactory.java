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

import java.io.IOException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.pool2.BaseKeyedPooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.poi.util.StringUtil;
import org.codelibs.fess.crawler.client.smb.SmbAuthentication;
import org.codelibs.fess.crawler.exception.CrawlerSystemException;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;
import com.hierynomus.smbj.session.Session;

public class PooledSmbSessionFactory extends BaseKeyedPooledObjectFactory<SmbSessionKey, Session> {

    private final SmbConfig config;
    private final SmbAuthentication[] authentications;

    public PooledSmbSessionFactory(final SmbConfig smbConfig, final SmbAuthentication[] smbAuthentications) {
        this.config = smbConfig;
        this.authentications = smbAuthentications;
    }

    @Override
    public Session create(final SmbSessionKey key) throws Exception {
        int port = key.getPort();
        if (port == -1) {
            port = 139;
        }
        @SuppressWarnings("resource") // close client in destroyObject
        final SMBClient client = new SMBClient(config);
        final Connection connection = client.connect(key.getHost(), port);
        for (final SmbAuthentication auth : authentications) {
            if (key.getHost().equals(auth.getServer()) && port == auth.getPort()) {
                final String domain = auth.getDomain();
                final AuthenticationContext ac = new AuthenticationContext(auth.getUsername(), auth.getPassword().toCharArray(),
                        StringUtil.isBlank(domain) ? "WORKGROUP" : domain);
                return connection.authenticate(ac);
            }
        }
        closeConnection(connection);
        throw new CrawlerSystemException("Cannot find a proper authentication for " + key);
    }

    @Override
    public PooledObject<Session> wrap(final Session value) {
        return new DefaultPooledObject<>(value);
    }

    @Override
    public void destroyObject(final SmbSessionKey key, final PooledObject<Session> p) throws Exception {
        closeConnection(p.getObject().getConnection());
    }

    private void closeConnection(final Connection connection) throws IOException {
        if (connection == null) {
            return;
        }
        try {
            connection.close(true);
        } finally {
            IOUtils.closeQuietly(connection.getClient());
        }
    }
}
