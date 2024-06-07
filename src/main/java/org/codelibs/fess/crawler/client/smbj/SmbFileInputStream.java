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
package org.codelibs.fess.crawler.client.smbj;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class SmbFileInputStream extends InputStream {

    private final InputStream parent;

    public SmbFileInputStream(final SmbFile smbFile, final int threshold) {
        parent = smbFile.getInputStream(threshold);
    }

    @Override
    public int read() throws IOException {
        return parent.read();
    }

    @Override
    public int hashCode() {
        return parent.hashCode();
    }

    @Override
    public boolean equals(final Object obj) {
        return parent.equals(obj);
    }

    @Override
    public int read(final byte[] b) throws IOException {
        return parent.read(b);
    }

    @Override
    public int read(final byte[] b, final int off, final int len) throws IOException {
        return parent.read(b, off, len);
    }

    @Override
    public String toString() {
        return parent.toString();
    }

    @Override
    public byte[] readAllBytes() throws IOException {
        return parent.readAllBytes();
    }

    @Override
    public byte[] readNBytes(final int len) throws IOException {
        return parent.readNBytes(len);
    }

    @Override
    public int readNBytes(final byte[] b, final int off, final int len) throws IOException {
        return parent.readNBytes(b, off, len);
    }

    @Override
    public long skip(final long n) throws IOException {
        return parent.skip(n);
    }

    @Override
    public void skipNBytes(final long n) throws IOException {
        parent.skipNBytes(n);
    }

    @Override
    public int available() throws IOException {
        return parent.available();
    }

    @Override
    public void close() throws IOException {
        parent.close();
    }

    @Override
    public void mark(final int readlimit) {
        parent.mark(readlimit);
    }

    @Override
    public void reset() throws IOException {
        parent.reset();
    }

    @Override
    public boolean markSupported() {
        return parent.markSupported();
    }

    @Override
    public long transferTo(final OutputStream out) throws IOException {
        return parent.transferTo(out);
    }

}
