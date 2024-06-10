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

import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.codelibs.core.exception.IORuntimeException;
import org.codelibs.fess.crawler.client.smbj.pool.SmbSessionLoader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.Share;
import com.rapid7.client.dcerpc.dto.ContextHandle;
import com.rapid7.client.dcerpc.mssamr.SecurityAccountManagerService;
import com.rapid7.client.dcerpc.mssamr.dto.DomainHandle;
import com.rapid7.client.dcerpc.mssamr.dto.GroupHandle;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithAttributes;
import com.rapid7.client.dcerpc.mssamr.dto.MembershipWithName;
import com.rapid7.client.dcerpc.mssamr.dto.ServerHandle;
import com.rapid7.client.dcerpc.transport.RPCTransport;
import com.rapid7.client.dcerpc.transport.SMBTransportFactories;

public class SmbSession implements Closeable {

    private static final Logger logger = LoggerFactory.getLogger(SmbSession.class);

    protected Session session;

    protected com.rapid7.client.dcerpc.dto.SID domainSid;

    public SmbSession(final Session session) {
        this.session = session;
    }

    @Override
    public void close() throws IOException {
        session.getConnection().getClient().close();
    }

    public Share connectShare(final String shareName) {
        return session.connectShare(shareName);
    }

    public Session getSession() {
        return session;
    }

    protected void loadDomainSid() {
        if (logger.isDebugEnabled()) {
            logger.debug("loading domain sid...");
        }
        try {
            final RPCTransport transport = SMBTransportFactories.SRVSVC.getTransport(session);
            final SecurityAccountManagerService samrService = new SecurityAccountManagerService(transport);
            final ServerHandle serverHandle = samrService.openServer();
            final MembershipWithName[] domains = samrService.getDomainsForServer(serverHandle);
            if (logger.isDebugEnabled()) {
                logger.debug("domains: {}", Arrays.toString(domains));
            }
            if (domains.length > 0) {
                domainSid = samrService.getSIDForDomain(serverHandle, domains[0].getName());
            }
            closeHandle(samrService, serverHandle);
        } catch (final IOException e) {
            throw new IORuntimeException(e);
        }
    }

    public SID[] getGroupMembers(final SID groupSid) {
        if (domainSid == null) {
            loadDomainSid();
        }

        if (logger.isDebugEnabled()) {
            logger.debug("get group members with {}", domainSid);
        }

        final List<SID> memberSids = new ArrayList<>();
        try {
            final RPCTransport transport = SMBTransportFactories.SRVSVC.getTransport(session);
            final SecurityAccountManagerService samrService = new SecurityAccountManagerService(transport);
            final ServerHandle serverHandle = samrService.openServer();
            final DomainHandle domainHandle = samrService.openDomain(serverHandle, domainSid);
            final long groupRID = groupSid.getSubAuthorities()[groupSid.getSubAuthorities().length - 1];
            final GroupHandle groupHandle = samrService.openGroup(domainHandle, groupRID);
            final MembershipWithAttributes[] memberships = samrService.getMembersForGroup(groupHandle);
            if (logger.isDebugEnabled()) {
                logger.debug("memberships: {}", Arrays.toString(memberships));
            }
            for (final MembershipWithAttributes membership : memberships) {
                final SID memberSid = new SID(fromSid(domainSid.resolveRelativeID(membership.getRelativeID())), new SmbSessionLoader(this));
                memberSids.add(memberSid);
            }
            closeHandle(samrService, groupHandle);
            closeHandle(samrService, domainHandle);
            closeHandle(samrService, serverHandle);
        } catch (final IOException e) {
            throw new IORuntimeException(e);
        }
        if (logger.isDebugEnabled()) {
            logger.debug("group sids: {}", memberSids);
        }
        return memberSids.toArray(n -> new SID[n]);
    }

    protected boolean closeHandle(SecurityAccountManagerService samrService, ContextHandle handle) {
        try {
            return samrService.closeHandle(handle);
        } catch (IOException e) {
            logger.warn("Failed to close " + handle, e);
        }
        return false;
    }

    protected static com.hierynomus.msdtyp.SID fromSid(final com.rapid7.client.dcerpc.dto.SID sid) {
        return new com.hierynomus.msdtyp.SID(sid.getRevision(), sid.getIdentifierAuthority(), sid.getSubAuthorities());
    }
}
