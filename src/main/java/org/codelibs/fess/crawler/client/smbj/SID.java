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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.smb.SMBBuffer;
import com.rapid7.client.dcerpc.mslsad.LocalSecurityAuthorityService;
import com.rapid7.client.dcerpc.mslsad.dto.PolicyHandle;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;

public class SID extends com.hierynomus.msdtyp.SID {
    private static final Logger logger = LoggerFactory.getLogger(SID.class);

    private final com.hierynomus.msdtyp.SID parent;
    private String domainName;
    private String accountName;

    public SID(final com.hierynomus.msdtyp.SID parent, final SmbFile smbFile) {
        this.parent = parent;
        final String sid = parent.toString();
        smbFile.openSession(session -> {
            final RPCTransport transport = SMBTransportFactories.LSASVC.getTransport(session);
            final LocalSecurityAuthorityService lsaService = new LocalSecurityAuthorityService(transport);

            final PolicyHandle policyHandle = lsaService.openPolicyHandle();
            final String[] lookupNames = lsaService.lookupNamesForSIDs(policyHandle, com.rapid7.client.dcerpc.dto.SID.fromString(sid));
            if (logger.isDebugEnabled()) {
                logger.debug("sid lookup: {} -> {}", sid, lookupNames);
            }
            if (lookupNames.length > 0) {
                accountName = lookupNames[0];
            }
            if (lookupNames.length > 1) {
                domainName = lookupNames[1]; // TODO correct?
            }
        });
    }

    @Override
    public void write(final SMBBuffer buffer) {
        parent.write(buffer);
    }

    @Override
    public int byteCount() {
        return parent.byteCount();
    }

    @Override
    public String toString() {
        return parent.toString();
    }

    @Override
    public byte getRevision() {
        return parent.getRevision();
    }

    @Override
    public byte[] getSidIdentifierAuthority() {
        return parent.getSidIdentifierAuthority();
    }

    @Override
    public long[] getSubAuthorities() {
        return parent.getSubAuthorities();
    }

    @Override
    public boolean equals(final Object o) {
        return parent.equals(o);
    }

    @Override
    public int hashCode() {
        return parent.hashCode();
    }

    public String getAccountName() {
        return accountName;
    }

    public String getDomainName() {
        return domainName;
    }
}
