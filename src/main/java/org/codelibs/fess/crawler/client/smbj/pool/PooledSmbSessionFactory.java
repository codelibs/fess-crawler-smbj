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

import org.apache.commons.io.IOUtils;
import org.apache.commons.pool2.BaseKeyedPooledObjectFactory;
import org.apache.commons.pool2.PooledObject;
import org.apache.commons.pool2.impl.DefaultPooledObject;
import org.apache.poi.util.StringUtil;
import org.codelibs.fess.crawler.client.smb.SmbAuthentication;
import org.codelibs.fess.crawler.client.smbj.SmbSession;
import org.codelibs.fess.crawler.exception.CrawlerSystemException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.smbj.SMBClient;
import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.auth.AuthenticationContext;
import com.hierynomus.smbj.connection.Connection;

public class PooledSmbSessionFactory extends BaseKeyedPooledObjectFactory<SmbSessionKey, SmbSession> {

    private static final Logger logger = LoggerFactory.getLogger(PooledSmbSessionFactory.class);

    private final SmbConfig config;

    private final SmbAuthentication[] authentications;

    public PooledSmbSessionFactory(final SmbConfig smbConfig, final SmbAuthentication[] smbAuthentications) {
        this.config = smbConfig;
        this.authentications = smbAuthentications;
    }

    @Override
    public SmbSession create(final SmbSessionKey key) throws Exception {
        int port = key.getPort();
        if (port == -1) {
            port = 139;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("Creating a new session by key={}, port={}", key, port);
        }
        @SuppressWarnings("resource") // close client in destroyObject
        final SMBClient client = new SMBClient(config);
        if (logger.isDebugEnabled()) {
            logger.debug("Created SMBClient with " + //
                    "supportedDialects=" + config.getSupportedDialects() + //
                    ", signingRequired=" + config.isSigningRequired() + //
                    ", dfsEnabled=" + config.isDfsEnabled() + //
                    ", useMultiProtocolNegotiate=" + config.isUseMultiProtocolNegotiate() + //
                    ", readBufferSize=" + config.getReadBufferSize() + //
                    ", readTimeout=" + config.getReadTimeout() + //
                    ", writeBufferSize=" + config.getWriteBufferSize() + //
                    ", writeTimeout=" + config.getWriteTimeout() + //
                    ", transactBufferSize=" + config.getTransactBufferSize() + //
                    ", transactTimeout=" + config.getTransactTimeout() + //
                    ", soTimeout=" + config.getSoTimeout() + //
                    ", encryptData=" + config.isEncryptData());
        }
        final Connection connection = client.connect(key.getHost(), port);
        if (logger.isDebugEnabled()) {
            logger.debug("Created Connection: connected={}", connection.isConnected());
            logger.debug("The number of authentications is {}", authentications.length);
        }
        for (final SmbAuthentication auth : authentications) {
            if (key.getHost().equals(auth.getServer()) && port == auth.getPort()) {
                final String domain = auth.getDomain();
                final AuthenticationContext ac = new AuthenticationContext(auth.getUsername(), auth.getPassword().toCharArray(),
                        StringUtil.isBlank(domain) ? "WORKGROUP" : domain);
                if (logger.isDebugEnabled()) {
                    logger.debug("AuthenticationContext={}", ac);
                }
                return new SmbSession(connection.authenticate(ac));
            }
        }
        IOUtils.closeQuietly(client);
        throw new CrawlerSystemException("Cannot find a proper authentication for " + key);
    }

    @Override
    public PooledObject<SmbSession> wrap(final SmbSession value) {
        return new DefaultPooledObject<>(value);
    }

    @Override
    public void destroyObject(final SmbSessionKey key, final PooledObject<SmbSession> p) throws Exception {
        if (logger.isDebugEnabled()) {
            logger.debug("destroy session: key={}, session={}", key, p.getObject());
        }
        p.getObject().close();
    }

}
