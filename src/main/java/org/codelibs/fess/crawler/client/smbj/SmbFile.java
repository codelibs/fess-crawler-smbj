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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.function.Function;

import org.apache.commons.io.output.DeferredFileOutputStream;
import org.apache.commons.lang3.SystemUtils;
import org.apache.commons.pool2.impl.GenericKeyedObjectPool;
import org.codelibs.core.io.CopyUtil;
import org.codelibs.core.lang.StringUtil;
import org.codelibs.fess.crawler.client.smbj.pool.SmbSessionKey;
import org.codelibs.fess.crawler.exception.CrawlingAccessException;
import org.codelibs.fess.crawler.util.TemporaryFileInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.hierynomus.msdtyp.AccessMask;
import com.hierynomus.msdtyp.SecurityDescriptor;
import com.hierynomus.msdtyp.SecurityInformation;
import com.hierynomus.msfscc.FileAttributes;
import com.hierynomus.msfscc.fileinformation.FileBasicInformation;
import com.hierynomus.msfscc.fileinformation.FileIdBothDirectoryInformation;
import com.hierynomus.msfscc.fileinformation.FileStandardInformation;
import com.hierynomus.mssmb2.SMB2CreateDisposition;
import com.hierynomus.mssmb2.SMB2CreateOptions;
import com.hierynomus.mssmb2.SMB2ShareAccess;
import com.hierynomus.smbj.session.Session;
import com.hierynomus.smbj.share.DiskShare;
import com.hierynomus.smbj.share.File;
import com.hierynomus.smbj.share.Share;

public class SmbFile {
    private static final Logger logger = LoggerFactory.getLogger(SmbFile.class);

    private SmbSessionKey sessionKey;

    private final GenericKeyedObjectPool<SmbSessionKey, Session> sessionPool;

    private String shareName;

    private String path;

    private boolean hasFileInfo = false;

    private FileStandardInformation standardInfo;

    private FileBasicInformation basicInfo;

    private SecurityDescriptor securityDescriptor;

    private String fileName;

    private String protocol;

    private Boolean isFileObject;

    private Boolean isDirectoryObject;

    public SmbFile(final String url, final GenericKeyedObjectPool<SmbSessionKey, Session> sessionPool) {
        this.sessionPool = sessionPool;
        try {
            final URL u = new URL(url);
            protocol = u.getProtocol();
            sessionKey = new SmbSessionKey(u.getHost(), u.getPort());
            final String[] segments = u.getPath().split("/", 3);
            if (segments.length <= 1) {
                throw new CrawlingAccessException("Invalid SMB URL: " + url);
            }
            if (segments.length > 1) {
                shareName = segments[1];
            }
            if (segments.length > 2) {
                path = segments[2];
            } else {
                path = StringUtil.EMPTY;
            }

        } catch (final MalformedURLException e) {
            throw new CrawlingAccessException("Invalid url: " + url, e);
        }
    }

    public boolean isFile() {
        if (isFileObject == null) {
            isFileObject = existsObject(diskShare -> diskShare.fileExists(path));
        }
        return isFileObject;
    }

    public boolean isDirectory() {
        if (isDirectoryObject == null) {
            isDirectoryObject = existsObject(diskShare -> diskShare.folderExists(path));
        }
        return isDirectoryObject;
    }

    protected boolean existsObject(final Function<DiskShare, Boolean> func) {
        Session session = null;
        try {
            session = sessionPool.borrowObject(sessionKey);
            try (Share share = session.connectShare(shareName)) {
                if (share instanceof final DiskShare diskShare) {
                    return func.apply(diskShare);
                }
                if (logger.isDebugEnabled()) {
                    logger.debug("{}://{}/{}/{} is not DiskShare.", protocol, sessionKey, shareName, path, share);
                }
            }
        } catch (final Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to access {}://{}/{}/{}", protocol, sessionKey, shareName, path, e);
            }
            closeSession(session);
            session = null;
        } finally {
            if (session != null) {
                sessionPool.returnObject(sessionKey, session);
            }
        }
        return false;
    }

    protected synchronized void loadFileInfo() {
        if (hasFileInfo) {
            return;
        }

        Session session = null;
        try {
            session = sessionPool.borrowObject(sessionKey);
            try (Share share = session.connectShare(shareName)) {
                if (share instanceof final DiskShare diskShare) {
                    try (File file = diskShare.openFile(path, EnumSet.of(AccessMask.GENERIC_READ),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
                            SMB2CreateDisposition.FILE_OPEN, EnumSet.noneOf(SMB2CreateOptions.class))) {
                        fileName = getFileName(file);
                        standardInfo = file.getFileInformation(FileStandardInformation.class);
                        basicInfo = file.getFileInformation(FileBasicInformation.class);
                        securityDescriptor = file.getSecurityInformation(
                                EnumSet.of(SecurityInformation.OWNER_SECURITY_INFORMATION, SecurityInformation.DACL_SECURITY_INFORMATION));
                        return;
                    }
                }
                if (logger.isDebugEnabled()) {
                    logger.debug("{}://{}/{}/{} is not DiskShare.", protocol, sessionKey, shareName, path, share);
                }
            }
        } catch (final Exception e) {
            if (logger.isDebugEnabled()) {
                logger.debug("Failed to access {}://{}/{}/{}", protocol, sessionKey, shareName, path, e);
            }
            closeSession(session);
            session = null;
        } finally {
            hasFileInfo = true;
            if (session != null) {
                sessionPool.returnObject(sessionKey, session);
            }
        }
    }

    protected void closeSession(final Session session) {
        try {
            session.close();
        } catch (final IOException e) {
            logger.warn("Failed to close the session for " + sessionKey, e);
        }
    }

    protected String getFileName(final File file) {
        final String uncPath = file.getUncPath();
        int lastIndex = uncPath.lastIndexOf("\\");
        if (lastIndex == -1) {
            return uncPath;
        }
        return uncPath.substring(lastIndex + 1);
    }

    public long length() {
        if (!hasFileInfo) {
            loadFileInfo();
        }
        if (standardInfo == null) {
            return -1;
        }
        return standardInfo.getEndOfFile();
    }

    public long getContentLengthLong() {
        return length();
    }

    public long lastModified() {
        if (!hasFileInfo) {
            loadFileInfo();
        }
        if (basicInfo == null) {
            return 0;
        }
        return basicInfo.getLastWriteTime().toEpochMillis();
    }

    public long createTime() {
        if (!hasFileInfo) {
            loadFileInfo();
        }
        if (basicInfo == null) {
            return 0;
        }
        return basicInfo.getCreationTime().toEpochMillis();
    }

    public SID getOwnerUser() {
        if (!hasFileInfo) {
            loadFileInfo();
        }
        return new SID(securityDescriptor.getOwnerSid(), this);
    }

    public void openSession(final SessionCallback consumer) {
        Session session = null;
        try {
            session = sessionPool.borrowObject(sessionKey);
            consumer.accept(session);
        } catch (final Exception e) {
            closeSession(session);
            session = null;
            throw new CrawlingAccessException("Failed to process the session: " + sessionKey, e);
        } finally {
            if (session != null) {
                sessionPool.returnObject(sessionKey, session);
            }
        }
    }

    interface SessionCallback {
        void accept(Session session) throws Exception;
    }

    public boolean canRead() {
        return true; // TODO
    }

    public String getName() {
        if (!hasFileInfo) {
            loadFileInfo();
        }
        return fileName;
    }

    public SmbFile[] listFiles() {
        if (!isDirectory()) {
            return new SmbFile[0];
        }

        Session session = null;
        try {
            session = sessionPool.borrowObject(sessionKey);
            try (Share share = session.connectShare(shareName)) {
                if (share instanceof final DiskShare diskShare) {
                    final List<SmbFile> fileList = new ArrayList<>();
                    for (final FileIdBothDirectoryInformation f : diskShare.list(path)) {
                        final String fileName = f.getFileName();
                        if (".".equals(fileName) || "..".equals(fileName)) {
                            continue;
                        }
                        final StringBuilder buf = new StringBuilder(100);
                        buf.append(protocol)//
                                .append("://")//
                                .append(sessionKey.toString())//
                                .append('/')//
                                .append(shareName)//
                                .append('/')//
                                .append(path);
                        if (StringUtil.isNotEmpty(path) && !path.endsWith("/")) {
                            buf.append('/');
                        }
                        buf.append(fileName);
                        fileList.add(new SmbFile(buf.toString(), sessionPool));
                    }
                    return fileList.toArray(n -> new SmbFile[n]);
                }
                throw new CrawlingAccessException(toString() + " is not a directory. The type is " + share);
            }
        } catch (final Exception e) {
            closeSession(session);
            session = null;
            throw new CrawlingAccessException("Failed to get files in " + toString(), e);
        } finally {
            if (session != null) {
                sessionPool.returnObject(sessionKey, session);
            }
        }
    }

    @Override
    public String toString() {
        return protocol + "://" + sessionKey + "/" + shareName + "/" + path;
    }

    public InputStream getInputStream(final int threshold) {
        if (!isFile()) {
            throw new CrawlingAccessException(toString() + " is not a file.");
        }

        Session session = null;
        try {
            session = sessionPool.borrowObject(sessionKey);
            try (Share share = session.connectShare(shareName)) {
                if (share instanceof final DiskShare diskShare) {
                    try (File file = diskShare.openFile(path, EnumSet.of(AccessMask.GENERIC_READ),
                            EnumSet.of(FileAttributes.FILE_ATTRIBUTE_NORMAL), EnumSet.of(SMB2ShareAccess.FILE_SHARE_READ),
                            SMB2CreateDisposition.FILE_OPEN, EnumSet.noneOf(SMB2CreateOptions.class));
                            DeferredFileOutputStream dfos = DeferredFileOutputStream.builder().setThreshold(threshold)
                                    .setPrefix("crawler-SmbFile-").setSuffix(".out").setDirectory(SystemUtils.getJavaIoTmpDir()).get()) {
                        CopyUtil.copy(file.getInputStream(), dfos);
                        dfos.flush();

                        if (dfos.isInMemory()) {
                            return new ByteArrayInputStream(dfos.getData());
                        }
                        return new TemporaryFileInputStream(dfos.getFile());
                    }
                }
                throw new CrawlingAccessException(toString() + " is not a file. The type is " + share);
            }
        } catch (final Exception e) {
            closeSession(session);
            session = null;
            throw new CrawlingAccessException("Failed to access " + toString(), e);
        } finally {
            if (session != null) {
                sessionPool.returnObject(sessionKey, session);
            }
        }
    }
}
