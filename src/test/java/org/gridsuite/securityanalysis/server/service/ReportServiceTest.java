/**
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.commons.report.ReportNode;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.gridsuite.securityanalysis.server.computation.service.ReportService;
import org.gridsuite.securityanalysis.server.util.ContextConfigurationWithTestChannel;
import org.jetbrains.annotations.NotNull;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestClientException;

import java.io.IOException;
import java.util.Objects;
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfigurationWithTestChannel
public class ReportServiceTest {

    private static final UUID REPORT_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID REPORT_ERROR_UUID = UUID.fromString("9928181c-7977-4592-ba19-88027e4254e4");

    private static final String REPORT_JSON = "{\"version\":\"2.0\",\"reportRoot\":{\"messageKey\":\"test\",\"dictionaries\":{\"default\":{\"test\":\"a test\"}}}}";

    private MockWebServer server;

    @Autowired
    private ReportService reportService;

    @Before
    public void setUp() throws IOException {
        String mockServerUri = initMockWebServer();
        reportService.setReportServerBaseUri(mockServerUri);
    }

    @After
    public void tearDown() {
        try {
            server.shutdown();
        } catch (Exception e) {
            // Nothing to do
        }
    }

    private String initMockWebServer() throws IOException {
        server = new MockWebServer();
        server.start();

        final Dispatcher dispatcher = new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String requestPath = Objects.requireNonNull(request.getPath());
                if (requestPath.equals(String.format("/v1/reports/%s", REPORT_UUID))) {
                    assertEquals(REPORT_JSON, request.getBody().readUtf8());
                    return new MockResponse().setResponseCode(HttpStatus.OK.value());
                } else if (requestPath.equals(String.format("/v1/reports/%s?reportTypeFilter=SecurityAnalysis&errorOnReportNotFound=false", REPORT_UUID))) {
                    assertEquals("", request.getBody().readUtf8());
                    return new MockResponse().setResponseCode(HttpStatus.OK.value());
                } else {
                    return new MockResponse().setResponseCode(HttpStatus.NOT_FOUND.value()).setBody("Path not supported: " + request.getPath());
                }
            }
        };

        server.setDispatcher(dispatcher);

        // Ask the server for its URL. You'll need this to make HTTP requests.
        HttpUrl baseHttpUrl = server.url("");

        return baseHttpUrl.toString().substring(0, baseHttpUrl.toString().length() - 1);
    }

    @Test
    public void testSendReport() {
        ReportNode reporter = ReportNode.newRootReportNode().withMessageTemplate("test", "a test").build();
        reportService.sendReport(REPORT_UUID, reporter);
        assertThrows(RestClientException.class, () -> reportService.sendReport(REPORT_ERROR_UUID, reporter));
    }

    @Test
    public void testDeleteReport() {
        reportService.deleteReport(REPORT_UUID, "SecurityAnalysis");
        assertThrows(RestClientException.class, () -> reportService.deleteReport(REPORT_ERROR_UUID, "SecurityAnalysis"));
    }
}
