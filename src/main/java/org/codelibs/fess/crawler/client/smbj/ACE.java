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

import org.codelibs.fess.crawler.client.smbj.pool.SmbSessionLoader;

import com.hierynomus.msdtyp.ace.AceHeader;
import com.hierynomus.smb.SMBBuffer;

public class ACE {

    private final com.hierynomus.msdtyp.ace.ACE parent;

    private final SmbSessionLoader sessionLoader;

    public ACE(final com.hierynomus.msdtyp.ace.ACE parent, final SmbSessionLoader sessionLoader) {
        this.parent = parent;
        this.sessionLoader = sessionLoader;
    }

    public final void write(final SMBBuffer buffer) {
        parent.write(buffer);
    }

    @Override
    public int hashCode() {
        return parent.hashCode();
    }

    public AceHeader getAceHeader() {
        return parent.getAceHeader();
    }

    public SID getSid() {
        return new SID(parent.getSid(), sessionLoader);
    }

    public long getAccessMask() {
        return parent.getAccessMask();
    }

    @Override
    public boolean equals(final Object obj) {
        return parent.equals(obj);
    }

    @Override
    public String toString() {
        return parent.getSid() + ":" + getAceHeader().getAceType();
    }
}
