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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Objects;

import org.codelibs.fess.crawler.exception.CrawlerSystemException;

public class SmbSessionKey {
    private String host;
    private int port;

    public SmbSessionKey(final String url) {
        try {
            final URL u = new URL(url);
            host = u.getHost();
            port = u.getPort();
        } catch (final MalformedURLException e) {
            throw new CrawlerSystemException("Invalid url: " + url, e);
        }
    }

    public SmbSessionKey(final String host, final int port) {
        this.host = host;
        this.port = port;
    }

    @Override
    public String toString() {
        if (port == -1) {
            return host;
        }
        return host + ":" + port;
    }

    @Override
    public int hashCode() {
        return Objects.hash(host, port);
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }
        if ((obj == null) || (getClass() != obj.getClass())) {
            return false;
        }
        final SmbSessionKey other = (SmbSessionKey) obj;
        return Objects.equals(host, other.host) && port == other.port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }
}
