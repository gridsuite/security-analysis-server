/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.gridsuite.securityanalysis.server.SecurityAnalysisApplication;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.stream.binder.test.TestChannelBinderConfiguration;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringRunner;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.Assert.assertEquals;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@SpringBootTest
@RunWith(SpringRunner.class)
@ContextConfiguration(classes = {SecurityAnalysisApplication.class, TestChannelBinderConfiguration.class})
public class ActionsServiceTest {

    private static final int DATA_BUFFER_LIMIT = 256 * 1024; // AbstractJackson2Decoder.maxInMemorySize

    private static final String NETWORK_UUID = "7928181c-7977-4592-ba19-88027e4254e4";

    private static final String VARIANT_ID = "variant_id";

    private static final String LIST_NAME = "myList";

    private static final String VERY_LARGE_LIST_NAME = "veryLargelist";

    private static final Contingency CONTINGENCY = new Contingency("c1", new BranchContingency("b1"));

    private static final Contingency CONTINGENCY_VARIANT = new Contingency("c2", new BranchContingency("b2"));

    @Autowired
    private ObjectMapper objectMapper;

    private MockWebServer server;

    @Autowired
    private ActionsService actionsService;

    @Before
    public void setUp() throws IOException {
        String mockServerUri = initMockWebServer();
        actionsService.setActionServiceBaseUri(mockServerUri);
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

        String jsonExpected = objectMapper.writeValueAsString(List.of(CONTINGENCY));
        String veryLargeJsonExpected = objectMapper.writeValueAsString(createVeryLargeList());
        String jsonVariantExpected = objectMapper.writeValueAsString(List.of(CONTINGENCY_VARIANT));

        final Dispatcher dispatcher = new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String requestPath = Objects.requireNonNull(request.getPath());
                if (requestPath.equals(String.format("/v1/contingency-lists/%s/export?networkUuid=%s&variantId=%s", LIST_NAME, NETWORK_UUID, VARIANT_ID))) {
                    return new MockResponse().setResponseCode(HttpStatus.OK.value())
                            .setBody(jsonVariantExpected)
                            .addHeader("Content-Type", "application/json; charset=utf-8");
                } else if (requestPath.equals(String.format("/v1/contingency-lists/%s/export?networkUuid=%s", LIST_NAME, NETWORK_UUID))) {
                    return new MockResponse().setResponseCode(HttpStatus.OK.value())
                        .setBody(jsonExpected)
                        .addHeader("Content-Type", "application/json; charset=utf-8");
                } else if (requestPath.equals(String.format("/v1/contingency-lists/%s/export?networkUuid=%s&variantId=%s", VERY_LARGE_LIST_NAME, NETWORK_UUID, VARIANT_ID))
                           || requestPath.equals(String.format("/v1/contingency-lists/%s/export?networkUuid=%s", VERY_LARGE_LIST_NAME, NETWORK_UUID))) {
                    return new MockResponse().setResponseCode(HttpStatus.OK.value())
                            .setBody(veryLargeJsonExpected)
                            .addHeader("Content-Type", "application/json; charset=utf-8");
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

    private List<Contingency> createVeryLargeList() {
        return IntStream.range(0, DATA_BUFFER_LIMIT).mapToObj(i -> new Contingency("l" + i, new BranchContingency("l" + i))).collect(Collectors.toList());
    }

    @Test
    public void test() {
        List<Contingency> list = actionsService.getContingencyList(LIST_NAME, UUID.fromString(NETWORK_UUID), null);
        assertEquals(List.of(CONTINGENCY), list);
        list = actionsService.getContingencyList(LIST_NAME, UUID.fromString(NETWORK_UUID), VARIANT_ID);
        assertEquals(List.of(CONTINGENCY_VARIANT), list);
    }

    @Test
    public void testVeryLargeList() {
        // DataBufferLimitException should not be thrown with this message : "Exceeded limit on max bytes to buffer : DATA_BUFFER_LIMIT"
        List<Contingency> list = actionsService.getContingencyList(VERY_LARGE_LIST_NAME, UUID.fromString(NETWORK_UUID), null);
        assertEquals(createVeryLargeList(), list);
        list = actionsService.getContingencyList(VERY_LARGE_LIST_NAME, UUID.fromString(NETWORK_UUID), VARIANT_ID);
        assertEquals(createVeryLargeList(), list);
    }
}
