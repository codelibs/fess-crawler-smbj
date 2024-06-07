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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.annotation.Resource;

import org.apache.commons.pool2.impl.GenericKeyedObjectPool;
import org.apache.commons.pool2.impl.GenericKeyedObjectPoolConfig;
import org.codelibs.core.exception.IORuntimeException;
import org.codelibs.core.io.CloseableUtil;
import org.codelibs.core.io.FileUtil;
import org.codelibs.core.io.InputStreamUtil;
import org.codelibs.core.lang.StringUtil;
import org.codelibs.core.timer.TimeoutManager;
import org.codelibs.core.timer.TimeoutTask;
import org.codelibs.fess.crawler.Constants;
import org.codelibs.fess.crawler.builder.RequestDataBuilder;
import org.codelibs.fess.crawler.client.AbstractCrawlerClient;
import org.codelibs.fess.crawler.client.AccessTimeoutTarget;
import org.codelibs.fess.crawler.client.smb.SmbAuthentication;
import org.codelibs.fess.crawler.client.smbj.pool.PooledSmbSessionFactory;
import org.codelibs.fess.crawler.client.smbj.pool.SmbSessionKey;
import org.codelibs.fess.crawler.entity.RequestData;
import org.codelibs.fess.crawler.entity.ResponseData;
import org.codelibs.fess.crawler.exception.ChildUrlsException;
import org.codelibs.fess.crawler.exception.CrawlerSystemException;
import org.codelibs.fess.crawler.exception.CrawlingAccessException;
import org.codelibs.fess.crawler.exception.MaxLengthExceededException;
import org.codelibs.fess.crawler.helper.ContentLengthHelper;
import org.codelibs.fess.crawler.helper.MimeTypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.smbj.SmbConfig;
import com.hierynomus.smbj.SmbConfig.Builder;
import com.hierynomus.smbj.session.Session;

import jcifs.smb.NtlmPasswordAuthenticator;

/**
 * @author shinsuke
 *
 */
public class SmbClient extends AbstractCrawlerClient {
    private static final Logger logger = LoggerFactory.getLogger(SmbClient.class);

    public static final String SMB_AUTHENTICATIONS_PROPERTY = "smbAuthentications";

    public static final String SMB_ALLOWED_SID_ENTRIES = "smbAllowedSidEntries";

    public static final String SMB_DENIED_SID_ENTRIES = "smbDeniedSidEntries";

    public static final String SMB_CREATE_TIME = "smbCreateTime";

    public static final String SMB_OWNER_ATTRIBUTES = "smbOwnerAttributes";

    protected String charset = Constants.UTF_8;

    protected boolean resolveSids = true;

    @Resource
    protected ContentLengthHelper contentLengthHelper;

    protected GenericKeyedObjectPool<SmbSessionKey, Session> sessionPool;

    protected int maxCachedContentSize = 1024 * 1024; //1mb

    @Override
    public synchronized void init() {
        if (sessionPool != null) {
            return;
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Initializing SmbClient...");
        }

        super.init();

        sessionPool = new GenericKeyedObjectPool<>(
                new PooledSmbSessionFactory(createSmbConfig(),
                        getInitParameter(SMB_AUTHENTICATIONS_PROPERTY, new SmbAuthentication[0], SmbAuthentication[].class)),
                createSmbPoolConfig());

        final String maxCachedContentSizeStr = System.getProperty("smbj.config.max_cache_content_size");
        if (StringUtil.isNotBlank(maxCachedContentSizeStr)) {
            maxCachedContentSize = Integer.parseInt(maxCachedContentSizeStr);
        }
    }

    protected GenericKeyedObjectPoolConfig<Session> createSmbPoolConfig() {
        final GenericKeyedObjectPoolConfig<Session> poolConfig = new GenericKeyedObjectPoolConfig<>();
        final String prefix = "smbj.pool.";
        System.getProperties().entrySet().stream().filter(e -> e.getKey().toString().startsWith(prefix)).forEach(e -> {
            final String key = e.getKey().toString().substring(prefix.length());
            if (e.getValue() instanceof final String value) {
                switch (key) {
                case "block_when_exhausted":
                    poolConfig.setBlockWhenExhausted(Boolean.parseBoolean(value));
                    break;
                case "evictor_shutdown_timeout":
                    poolConfig.setEvictorShutdownTimeout(Duration.ofMillis(Long.parseLong(value)));
                    break;
                case "fairness":
                    poolConfig.setFairness(Boolean.parseBoolean(value));
                    break;
                case "jmx_enabled":
                    poolConfig.setJmxEnabled(Boolean.parseBoolean(value));
                    break;
                case "jmx_name_base":
                    poolConfig.setJmxNameBase(value);
                    break;
                case "jmx_name_prefix":
                    poolConfig.setJmxNamePrefix(value);
                    break;
                case "lifo":
                    poolConfig.setLifo(Boolean.parseBoolean(value));
                    break;
                case "max_idle_per_key":
                    poolConfig.setMaxIdlePerKey(Integer.parseInt(value));
                    break;
                case "max_total":
                    poolConfig.setMaxTotal(Integer.parseInt(value));
                    break;
                case "max_total_per_key":
                    poolConfig.setMaxTotalPerKey(Integer.parseInt(value));
                    break;
                case "max_wait":
                    poolConfig.setMaxWait(Duration.ofMillis(Long.parseLong(value)));
                    break;
                case "min_evictable_idle_duration":
                    poolConfig.setMinEvictableIdleDuration(Duration.ofMillis(Long.parseLong(value)));
                    break;
                case "min_idle_per_key":
                    poolConfig.setMinIdlePerKey(Integer.parseInt(value));
                    break;
                case "num_tests_per_eviction_run":
                    poolConfig.setNumTestsPerEvictionRun(Integer.parseInt(value));
                    break;
                case "soft_min_evictable_idle_duration":
                    poolConfig.setSoftMinEvictableIdleDuration(Duration.ofMillis(Long.parseLong(value)));
                    break;
                case "test_on_borrow":
                    poolConfig.setTestOnBorrow(Boolean.parseBoolean(value));
                    break;
                case "test_on_create":
                    poolConfig.setTestOnCreate(Boolean.parseBoolean(value));
                    break;
                case "test_on_return":
                    poolConfig.setTestOnReturn(Boolean.parseBoolean(value));
                    break;
                case "test_while_idle":
                    poolConfig.setTestWhileIdle(Boolean.parseBoolean(value));
                    break;
                case "time_between_eviction_runs":
                    poolConfig.setTimeBetweenEvictionRuns(Duration.ofMillis(Long.parseLong(value)));
                    break;
                default:
                    logger.warn("Unknown setting: {}={}", e.getKey(), value);
                    break;
                }
            }
        });
        return poolConfig;
    }

    protected SmbConfig createSmbConfig() {
        final Builder builder = SmbConfig.builder();
        final String prefix = "smbj.";
        System.getProperties().entrySet().stream().filter(e -> e.getKey().toString().startsWith(prefix)).forEach(e -> {
            final String key = e.getKey().toString().substring(prefix.length());
            if (e.getValue() instanceof final String value) {
                switch (key) {
                case "buffer_size":
                    builder.withBufferSize(Integer.parseInt(value));
                    break;
                case "dfs_enabled":
                    builder.withDfsEnabled(Boolean.parseBoolean(value));
                    break;
                case "multi_protocol_negotiate":
                    builder.withMultiProtocolNegotiate(Boolean.parseBoolean(value));
                    break;
                case "encrypt_data":
                    builder.withEncryptData(Boolean.parseBoolean(value));
                    break;
                case "read_buffer_size":
                    builder.withReadBufferSize(Integer.parseInt(value));
                    break;
                case "read_timeout":
                    builder.withReadTimeout(Long.parseLong(value), TimeUnit.MILLISECONDS);
                    break;
                case "signing_required":
                    builder.withSigningRequired(Boolean.parseBoolean(value));
                    break;
                case "so_timeout":
                    builder.withSoTimeout(Long.parseLong(value), TimeUnit.MILLISECONDS);
                    break;
                case "timeout":
                    builder.withTimeout(Long.parseLong(value), TimeUnit.MILLISECONDS);
                    break;
                case "transact_timeout":
                    builder.withTransactTimeout(Long.parseLong(value), TimeUnit.MILLISECONDS);
                    break;
                case "write_buffer_size":
                    builder.withWriteBufferSize(Integer.parseInt(value));
                    break;
                case "write_timeout":
                    builder.withWriteTimeout(Long.parseLong(value), TimeUnit.MILLISECONDS);
                    break;
                default:
                    if (!key.startsWith("pool.") || !key.startsWith("config.")) {
                        logger.warn("Unknown setting: {}={}", e.getKey(), value);
                    }
                    break;
                }
            }
        });
        return builder.build();
    }

    @Override
    public void close() throws Exception {
        if (sessionPool != null) {
            sessionPool.close();
        }
    }

    /*
     * (non-Javadoc)
     *
     * @see org.codelibs.fess.crawler.client.CrawlerClient#doGet(java.lang.String)
     */
    @Override
    public ResponseData doGet(final String uri) {
        return processRequest(uri, true);
    }

    protected ResponseData processRequest(final String uri, final boolean includeContent) {
        if (sessionPool == null) {
            init();
        }

        // start
        AccessTimeoutTarget accessTimeoutTarget = null;
        TimeoutTask accessTimeoutTask = null;
        if (accessTimeout != null) {
            accessTimeoutTarget = new AccessTimeoutTarget(Thread.currentThread());
            accessTimeoutTask = TimeoutManager.getInstance().addTimeoutTarget(accessTimeoutTarget, accessTimeout, false);
        }

        try {
            return getResponseData(uri, includeContent);
        } finally {
            if (accessTimeoutTarget != null) {
                accessTimeoutTarget.stop();
                if (accessTimeoutTask != null && !accessTimeoutTask.isCanceled()) {
                    accessTimeoutTask.cancel();
                }
            }
        }
    }

    protected NtlmPasswordAuthenticator getAuthenticator(final SmbAuthentication smbAuthentication) {
        return new NtlmPasswordAuthenticator(smbAuthentication.getDomain() == null ? "" : smbAuthentication.getDomain(),
                smbAuthentication.getUsername(), smbAuthentication.getPassword());
    }

    protected ResponseData getResponseData(final String uri, final boolean includeContent) {
        final ResponseData responseData = new ResponseData();
        responseData.setMethod(Constants.GET_METHOD);
        final String filePath = preprocessUri(uri);
        responseData.setUrl(filePath);

        if (logger.isDebugEnabled()) {
            logger.debug("Creating SmbFile: {}", filePath);
        }

        final SmbFile file = new SmbFile(filePath, sessionPool);

        if (logger.isDebugEnabled()) {
            logger.debug("Processing SmbFile: {}", filePath);
        }

        try {
            if (file.isFile()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Checking SmbFile Size: {}", filePath);
                }
                responseData.setContentLength(file.length());
                checkMaxContentLength(responseData);
                responseData.setHttpStatusCode(Constants.OK_STATUS_CODE);
                responseData.setCharSet(geCharSet(file));
                responseData.setLastModified(new Date(file.lastModified()));
                responseData.addMetaData(SMB_CREATE_TIME, new Date(file.createTime()));
                try {
                    if (logger.isDebugEnabled()) {
                        logger.debug("Parsing SmbFile Owner: {}", filePath);
                    }
                    final SID ownerUser = file.getOwnerUser();
                    if (ownerUser != null) {
                        final String[] ownerAttributes = { ownerUser.getAccountName(), ownerUser.getDomainName() };
                        responseData.addMetaData(SMB_OWNER_ATTRIBUTES, ownerAttributes);
                    }
                } catch (final Exception e) {
                    throw new CrawlingAccessException("Cannot get owner of the file: " + filePath, e);
                }

                if (logger.isDebugEnabled()) {
                    logger.debug("Parsing SmbFile ACL: {}", filePath);
                }
                processAccessControlEntries(responseData, file);
                //                final Map<String, List<String>> headerFieldMap = file.getHeaderFields();
                //                if (headerFieldMap != null) {
                //                    for (final Map.Entry<String, List<String>> entry : headerFieldMap.entrySet()) {
                //                        responseData.addMetaData(entry.getKey(), entry.getValue());
                //                    }
                //                }

                if (file.canRead()) {
                    final MimeTypeHelper mimeTypeHelper = crawlerContainer.getComponent("mimeTypeHelper");
                    if (includeContent) {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Parsing SmbFile Content: {}", filePath);
                        }
                        if (file.getContentLengthLong() < maxCachedContentSize) {
                            try (InputStream contentStream = new BufferedInputStream(new SmbFileInputStream(file, maxCachedContentSize))) {
                                responseData.setResponseBody(InputStreamUtil.getBytes(contentStream));
                            } catch (final Exception e) {
                                logger.warn("I/O Exception.", e);
                                responseData.setHttpStatusCode(Constants.SERVER_ERROR_STATUS_CODE);
                            }
                        } else {
                            File outputFile = null;
                            try {
                                outputFile = File.createTempFile("crawler-SmbClient-", ".out");
                                copy(file, outputFile);
                                responseData.setResponseBody(outputFile, true);
                            } catch (final Exception e) {
                                logger.warn("I/O Exception.", e);
                                responseData.setHttpStatusCode(Constants.SERVER_ERROR_STATUS_CODE);
                                FileUtil.deleteInBackground(outputFile);
                            }
                        }
                        if (logger.isDebugEnabled()) {
                            logger.debug("Parsing SmbFile MIME Type: {}", filePath);
                        }
                        try (final InputStream is = responseData.getResponseBody()) {
                            responseData.setMimeType(mimeTypeHelper.getContentType(is, file.getName()));
                        } catch (final Exception e) {
                            responseData.setMimeType(mimeTypeHelper.getContentType(null, file.getName()));
                        }
                    } else {
                        if (logger.isDebugEnabled()) {
                            logger.debug("Parsing SmbFile MIME Type: {}", filePath);
                        }
                        try (final InputStream is = new SmbFileInputStream(file, maxCachedContentSize)) {
                            responseData.setMimeType(mimeTypeHelper.getContentType(is, file.getName()));
                        } catch (final Exception e) {
                            responseData.setMimeType(mimeTypeHelper.getContentType(null, file.getName()));
                        }
                    }
                    if (contentLengthHelper != null) {
                        final long maxLength = contentLengthHelper.getMaxLength(responseData.getMimeType());
                        if (responseData.getContentLength() > maxLength) {
                            throw new MaxLengthExceededException("The content length (" + responseData.getContentLength()
                                    + " byte) is over " + maxLength + " byte. The url is " + filePath);
                        }
                    }
                } else {
                    // Forbidden
                    responseData.setHttpStatusCode(Constants.FORBIDDEN_STATUS_CODE);
                    responseData.setMimeType(APPLICATION_OCTET_STREAM);
                }
            } else if (file.isDirectory()) {
                if (logger.isDebugEnabled()) {
                    logger.debug("Parsing SmbFile Directory: {}", filePath);
                }
                final Set<RequestData> requestDataSet = new HashSet<>(100);
                if (includeContent) {
                    final SmbFile[] files = file.listFiles();
                    if (files != null) {
                        for (final SmbFile f : files) {
                            final String chileUri = f.toString();
                            requestDataSet.add(RequestDataBuilder.newRequestData().get().url(chileUri).build());
                        }
                    }
                }
                throw new ChildUrlsException(requestDataSet, this.getClass().getName() + "#getResponseData");
            } else {
                responseData.setHttpStatusCode(Constants.NOT_FOUND_STATUS_CODE);
                responseData.setCharSet(charset);
                responseData.setContentLength(0);
            }
        } catch (final CrawlerSystemException e) {
            CloseableUtil.closeQuietly(responseData);
            throw e;
        } catch (final Exception e) {
            CloseableUtil.closeQuietly(responseData);
            throw new CrawlingAccessException("Could not access " + uri, e);
        }

        return responseData;
    }

    protected void processAccessControlEntries(final ResponseData responseData, final SmbFile file) {
        /*
         try {
            final ACE[] aces = file.getSecurity(resolveSids);
            if (aces != null) {
                final Set<SID> sidAllowSet = new HashSet<>();
                final Set<SID> sidDenySet = new HashSet<>();
                for (final ACE ace : aces) {
                    if (logger.isDebugEnabled()) {
                        logger.debug("ACE:{}", ace);
                    }
                    processAllowedSIDs(file, ace.getSID(), ace.isAllow() ? sidAllowSet : sidDenySet);
                }
                responseData.addMetaData(SMB_ALLOWED_SID_ENTRIES, sidAllowSet.toArray(new SID[sidAllowSet.size()]));
                responseData.addMetaData(SMB_DENIED_SID_ENTRIES, sidDenySet.toArray(new SID[sidDenySet.size()]));
            }
        } catch (final IOException e) {
            throw new CrawlingAccessException("Could not access " + file.getPath(), e);
        }
        */
    }

    //    protected void processAllowedSIDs(final SmbFile file, final SID sid, final Set<SID> sidSet) {
    //        if (logger.isDebugEnabled()) {
    //            logger.debug("SID:{}", sid);
    //        }
    //        final byte type = sid.getRevision();
    //        sidSet.add(sid);
    //        if (type == SID.SidType.SID_TYPE_DOM_GRP || type == SID.SidType.SID_TYPE_ALIAS) {
    //            try {
    //                final CIFSContext context = file.getContext();
    //                final SID[] children = context.getSIDResolver().getGroupMemberSids(context, file.getServer(), sid.getDomainSid(),
    //                        sid.getRid(), jcifs.smb.SID.SID_FLAG_RESOLVE_SIDS);
    //                for (final SID child : children) {
    //                    if (!sidSet.contains(child)) {
    //                        processAllowedSIDs(file, child, sidSet);
    //                    }
    //                }
    //            } catch (final Exception e) {
    //                if (logger.isDebugEnabled()) {
    //                    logger.debug("Exception on SID processing.", e);
    //                }
    //            }
    //        }
    //    }

    protected String preprocessUri(final String uri) {
        if (StringUtil.isEmpty(uri)) {
            throw new CrawlerSystemException("The uri is empty.");
        }

        return uri;
    }

    protected String geCharSet(final SmbFile file) {
        return charset;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.codelibs.fess.crawler.client.CrawlerClient#doHead(java.lang.String)
     */
    @Override
    public ResponseData doHead(final String url) {
        try {
            final ResponseData responseData = processRequest(url, false);
            responseData.setMethod(Constants.HEAD_METHOD);
            return responseData;
        } catch (final ChildUrlsException e) {
            return null;
        }
    }

    private void copy(final SmbFile src, final File dest) {
        if (dest.exists() && !dest.canWrite()) {
            return;
        }
        try (BufferedInputStream in = new BufferedInputStream(new SmbFileInputStream(src, maxCachedContentSize));
                BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(dest))) {
            final byte[] buf = new byte[1024];
            int length;
            while (-1 < (length = in.read(buf))) {
                out.write(buf, 0, length);
                out.flush();
            }
        } catch (final IOException e) {
            throw new IORuntimeException(e);
        }
    }

    /**
     * @return the resolveSids
     */
    public boolean isResolveSids() {
        return resolveSids;
    }

    /**
     * @param resolveSids
     *            the resolveSids to set
     */
    public void setResolveSids(final boolean resolveSids) {
        this.resolveSids = resolveSids;
    }

    /**
     * @return the charset
     */
    public String getCharset() {
        return charset;
    }

    /**
     * @param charset
     *            the charset to set
     */
    public void setCharset(final String charset) {
        this.charset = charset;
    }

}
