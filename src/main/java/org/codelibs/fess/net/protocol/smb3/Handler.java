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
package org.codelibs.fess.net.protocol.smb3;

import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;

public class Handler extends URLStreamHandler {

    static final URLStreamHandler SMB_HANDLER = new Handler();

    @Override
    protected int getDefaultPort() {
        return 139;
    }

    @Override
    public URLConnection openConnection(final URL u) throws IOException {
        return null;
    }

    @Override
    protected void parseURL(final URL u, String spec, final int start, int limit) {
        final String host = u.getHost();
        String path, ref;
        int port;

        if ("smb3://".equals(spec)) {
            spec = "smb3:////";
            limit += 2;
        } else if (!spec.startsWith("smb3://") && host != null && host.length() == 0) {
            spec = "//" + spec;
            limit += 2;
        }
        super.parseURL(u, spec, start, limit);
        path = u.getPath();
        ref = u.getRef();
        if (ref != null) {
            path += '#' + ref;
        }
        port = u.getPort();
        if (port == -1) {
            port = getDefaultPort();
        }
        setURL(u, "smb", u.getHost(), port, u.getAuthority(), u.getUserInfo(), path, u.getQuery(), null);
    }
}
