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

import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_ALIAS;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_COMPUTER;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_DELETED;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_DOMAIN;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_DOM_GRP;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_INVALID;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_LABEL;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_UNKNOWN;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_USER;
import static com.hierynomus.msdtyp.SID.SidType.SID_TYPE_WKN_GRP;

import java.util.Arrays;

import org.apache.commons.io.IOUtils;
import org.codelibs.fess.crawler.client.smbj.pool.SmbSessionLoader;
import org.codelibs.fess.crawler.exception.CrawlingAccessException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.smb.SMBBuffer;
import com.rapid7.client.dcerpc.mslsad.LocalSecurityAuthorityService;
import com.rapid7.client.dcerpc.mslsad.dto.PolicyHandle;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;

public class SID extends com.hierynomus.msdtyp.SID {
    private static final Logger logger = LoggerFactory.getLogger(SID.class);

    protected final com.hierynomus.msdtyp.SID parent;

    protected SmbSessionLoader sessionLoader;

    protected String domainName;

    protected String accountName;

    protected SidType sidType;

    public SID(final com.hierynomus.msdtyp.SID parent, final SmbSessionLoader sessionLoader) {
        this.parent = parent;
        this.sessionLoader = sessionLoader;

        final long[] subAuthorities = getSubAuthorities();
        if (subAuthorities.length > 0) {
            final long lastSubAuthority = subAuthorities[subAuthorities.length - 1];
            if (isDomainGroup(lastSubAuthority)) {
                sidType = SID_TYPE_DOM_GRP;
            } else if (isUser(lastSubAuthority)) {
                sidType = SID_TYPE_USER;
            } else if (isBuiltinGroup(lastSubAuthority)) {
                sidType = SID_TYPE_WKN_GRP;
            } else if (isComputer(lastSubAuthority)) {
                sidType = SID_TYPE_COMPUTER;
            } else if (isAlias(lastSubAuthority)) {
                sidType = SID_TYPE_ALIAS;
            } else if (isDomain(lastSubAuthority)) {
                sidType = SID_TYPE_DOMAIN;
            } else if (isDeleted(lastSubAuthority)) {
                sidType = SID_TYPE_DELETED;
            } else if (isInvalid(lastSubAuthority)) {
                sidType = SID_TYPE_INVALID;
            } else if (isLabel(lastSubAuthority)) {
                sidType = SID_TYPE_LABEL;
            }
            if (logger.isDebugEnabled()) {
                logger.debug("lastSubAuthority={}, sidType={}", lastSubAuthority, sidType);
            }
        }
        if (sidType == null) {
            sidType = SID_TYPE_UNKNOWN;
        }
    }

    protected void loadAccountAndDomainName() {
        final String sid = parent.toString();
        SmbSession session = null;
        try {
            session = sessionLoader.borrowObject();
            final RPCTransport transport = SMBTransportFactories.LSASVC.getTransport(session.getSession());
            final LocalSecurityAuthorityService lsaService = new LocalSecurityAuthorityService(transport);

            final PolicyHandle policyHandle = lsaService.openPolicyHandle();
            try {
                final String[] lookupNames = lsaService.lookupNamesForSIDs(policyHandle, com.rapid7.client.dcerpc.dto.SID.fromString(sid));
                if (logger.isDebugEnabled()) {
                    logger.debug("sid lookup: {} -> {}", sid, Arrays.toString(lookupNames));
                }
                if (lookupNames.length > 0) {
                    accountName = lookupNames[0];
                }
                if (lookupNames.length > 1) {
                    domainName = lookupNames[1]; // TODO correct?
                }
            } finally {
                lsaService.closePolicyHandle(policyHandle);
            }
            sessionLoader.returnObject(session);
        } catch (final Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to access {}", sid, e);
            }
            IOUtils.closeQuietly(session);
        }
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
        if (accountName == null) {
            return parent.toString() + ":" + sidType;
        }
        return parent.toString() + "(" + accountName + "):" + sidType;
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
        if (accountName == null) {
            loadAccountAndDomainName();
        }
        return accountName;
    }

    public String getDomainName() {
        if (accountName == null) {
            loadAccountAndDomainName();
        }
        return domainName;
    }

    public SidType getSidType() {
        return sidType;
    }

    protected boolean isDomainGroup(final long subAuthority) {
        return subAuthority >= 512 && subAuthority <= 519;
    }

    protected boolean isUser(final long subAuthority) {
        return subAuthority >= 500 && subAuthority <= 999;
    }

    protected boolean isBuiltinGroup(final long subAuthority) {
        return subAuthority == 544 || subAuthority == 545 || subAuthority == 546;
    }

    protected boolean isComputer(final long subAuthority) {
        return subAuthority >= 1000;
    }

    protected boolean isAlias(final long subAuthority) {
        return subAuthority >= 544 && subAuthority <= 552;
    }

    protected boolean isDomain(final long subAuthority) {
        return subAuthority >= 100 && subAuthority < 200;
    }

    protected boolean isDeleted(final long subAuthority) {
        return false; // TODO
    }

    protected boolean isInvalid(final long subAuthority) {
        return false; // TODO
    }

    protected boolean isLabel(final long subAuthority) {
        return false; // TODO
    }

    public SID[] getGroupMemberSids() {
        if (logger.isDebugEnabled()) {
            logger.debug("load group members from {}", this);
        }
        SmbSession session = null;
        try {
            session = sessionLoader.borrowObject();
            final SID[] memberSids = session.getGroupMembers(this);
            if (logger.isDebugEnabled()) {
                logger.debug("group members: {}", Arrays.toString(memberSids));
            }
            sessionLoader.returnObject(session);
            return memberSids;
        } catch (final Exception e) {
            IOUtils.closeQuietly(session);
            throw new CrawlingAccessException("Failed to access group members for " + this, e);
        }
    }

}
