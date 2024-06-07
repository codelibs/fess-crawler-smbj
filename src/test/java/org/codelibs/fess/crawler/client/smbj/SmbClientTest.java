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

import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.codelibs.fess.crawler.client.smb.SmbAuthentication;
import org.codelibs.fess.crawler.container.StandardCrawlerContainer;
import org.codelibs.fess.crawler.entity.ResponseData;
import org.codelibs.fess.crawler.exception.ChildUrlsException;
import org.codelibs.fess.crawler.helper.impl.MimeTypeHelperImpl;
import org.dbflute.utflute.core.PlainTestCase;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

/**
 * @author shinsuke
 *
 */
public class SmbClientTest extends PlainTestCase {
    static final Logger logger = Logger.getLogger(SmbClientTest.class.getName());

    static final String version = "latest";

    static final String imageTag = "ghcr.io/servercontainers/samba:" + version;

    GenericContainer<?> server;

    private StandardCrawlerContainer crawlerContainer;

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        startServer();
        crawlerContainer = new StandardCrawlerContainer();
        crawlerContainer.prototype("smbClient", SmbClient.class);
        crawlerContainer.singleton("mimeTypeHelper", MimeTypeHelperImpl.class);
    }

    void startServer() {
        server = new GenericContainer<>(DockerImageName.parse(imageTag))//
                .withEnv("MODEL", "TimeCapsule")//
                .withEnv("AVAHI_NAME", "StorageServer")//
                .withEnv("SAMBA_CONF_LOG_LEVEL", "3")//
                .withEnv("GROUP_family", "1500")//
                .withEnv("ACCOUNT_alice", "alipass")//
                .withEnv("UID_alice", "1000")//
                .withEnv("GROUPS_alice", "family")//
                .withEnv("ACCOUNT_bob", "bobpass")//
                .withEnv("UID_bob", "1001")//
                .withEnv("GROUPS_bob", "family")//
                .withEnv("SAMBA_VOLUME_CONFIG_shared_home",
                        "[Home]; path=/shares/homes/%U; valid users = alice, bob, foo; guest ok = no; read only = no; browseable = yes")//
                .withEnv("SAMBA_VOLUME_CONFIG_aliceonly",
                        "[AliceShare]; path=/shares/alice; valid users = alice; guest ok = no; read only = no; browseable = yes")//
                .withEnv("SAMBA_VOLUME_CONFIG_bobonly",
                        "[BobShare]; path=/shares/bob; valid users = bob; guest ok = no; read only = no; browseable = yes")//
                .withEnv("SAMBA_VOLUME_CONFIG_guest", "[GuestShare];path = /shares/guest;guest ok = yes;browseable = yes")//
                .withCopyFileToContainer(MountableFile.forClasspathResource("/shares/"), "/shares")//
                .withExposedPorts(139);
        server.start();
    }

    @Override
    protected void tearDown() throws Exception {
        server.stop();
        super.tearDown();
    }

    public void test_doGet_dir() throws Exception {
        Integer port = server.getFirstMappedPort();
        try (SmbClient client = crawlerContainer.getComponent("smbClient")) {
            Map<String, Object> params = new HashMap<>();
            SmbAuthentication smbAuthentication = new SmbAuthentication();
            smbAuthentication.setServer(server.getHost());
            smbAuthentication.setPort(port);
            smbAuthentication.setUsername("alice");
            smbAuthentication.setPassword("alipass");
            smbAuthentication.setDomain("WORKGROUP");
            params.put(SmbClient.SMB_AUTHENTICATIONS_PROPERTY, new SmbAuthentication[] { smbAuthentication });
            client.setInitParameterMap(params);
            try {
                client.doGet("smb3://" + server.getHost() + ":" + port + "/Home");
                fail();
            } catch (ChildUrlsException e) {
                String[] urls = e.getChildUrlList().stream().map(req -> req.getUrl()).sorted().toArray(n -> new String[n]);
                assertEquals(2, urls.length);
                assertEquals("smb3://localhost:" + port + "/Home/folder4", urls[0]);
                assertEquals("smb3://localhost:" + port + "/Home/text4.txt", urls[1]);
            }
        }
    }

    public void test_doGet_file() throws Exception {
        Integer port = server.getFirstMappedPort();
        try (SmbClient client = crawlerContainer.getComponent("smbClient")) {
            Map<String, Object> params = new HashMap<>();
            SmbAuthentication smbAuthentication = new SmbAuthentication();
            smbAuthentication.setServer(server.getHost());
            smbAuthentication.setPort(port);
            smbAuthentication.setUsername("alice");
            smbAuthentication.setPassword("alipass");
            smbAuthentication.setDomain("WORKGROUP");
            params.put(SmbClient.SMB_AUTHENTICATIONS_PROPERTY, new SmbAuthentication[] { smbAuthentication });
            client.setInitParameterMap(params);
            ResponseData responseData = client.doGet("smb3://" + server.getHost() + ":" + port + "/Home/text4.txt");
            assertNotNull(responseData);
            assertEquals("smb3://localhost:" + port + "/Home/text4.txt", responseData.getUrl());
            assertEquals(7, responseData.getContentLength());
            assertEquals(200, responseData.getHttpStatusCode());
            assertEquals(0, responseData.getStatus());
            assertEquals("UTF-8", responseData.getCharSet());
            assertEquals("GET", responseData.getMethod());
        }
    }
}
