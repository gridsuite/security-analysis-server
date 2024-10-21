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
import mockwebserver3.Dispatcher;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import mockwebserver3.junit5.internal.MockWebServerExtension;
import okhttp3.Headers;
import okhttp3.HttpUrl;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.util.ContextConfigurationWithTestChannel;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 * @author Slimane Amar <slimane.amar at rte-france.com>
 */
@ExtendWith(MockWebServerExtension.class)
@SpringBootTest
@ContextConfigurationWithTestChannel
class ActionsServiceTest {

    private static final int DATA_BUFFER_LIMIT = 256 * 1024; // AbstractJackson2Decoder.maxInMemorySize

    private static final String NETWORK_UUID = "7928181c-7977-4592-ba19-88027e4254e4";

    private static final String VARIANT_ID = "variant_id";

    private static final String LIST_NAME = "myList";
    private static final String LIST_NAME_VARIANT = "myListVariant";

    private static final String VERY_LARGE_LIST_NAME = "veryLargelist";

    public static final String WRONG_ID = "wrongID";
    private static final ContingencyInfos CONTINGENCY = new ContingencyInfos(new Contingency("c1", new BranchContingency("b1")), Set.of(WRONG_ID), Set.of());

    private static final ContingencyInfos CONTINGENCY_VARIANT = new ContingencyInfos(new Contingency("c2", new BranchContingency("b2")));

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private ActionsService actionsService;

    @BeforeEach
    void setUp(final MockWebServer mockWebServer) throws Exception {
        final String mockServerUri = initMockWebServer(mockWebServer);
        actionsService.setActionServiceBaseUri(mockServerUri);
    }

    private String initMockWebServer(final MockWebServer server) throws IOException {
        String jsonExpected = objectMapper.writeValueAsString(List.of(CONTINGENCY));
        String veryLargeJsonExpected = objectMapper.writeValueAsString(createVeryLargeList());
        String jsonVariantExpected = objectMapper.writeValueAsString(List.of(CONTINGENCY_VARIANT));
        String jsonExpectedForList = objectMapper.writeValueAsString(List.of(CONTINGENCY, CONTINGENCY_VARIANT));

        final Dispatcher dispatcher = new Dispatcher() {
            @NotNull
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                String requestPath = Objects.requireNonNull(request.getPath());
                if (requestPath.equals(String.format("/v1/contingency-lists/contingency-infos/export?networkUuid=%s&variantId=%s&ids=%s", NETWORK_UUID, VARIANT_ID, LIST_NAME))) {
                    return new MockResponse(HttpStatus.OK.value(), Headers.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE), jsonVariantExpected);
                } else if (requestPath.equals(String.format("/v1/contingency-lists/contingency-infos/export?networkUuid=%s&ids=%s", NETWORK_UUID, LIST_NAME))) {
                    return new MockResponse(HttpStatus.OK.value(), Headers.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE), jsonExpected);
                } else if (requestPath.equals(String.format("/v1/contingency-lists/contingency-infos/export?networkUuid=%s&variantId=%s&ids=%s", NETWORK_UUID, VARIANT_ID, VERY_LARGE_LIST_NAME))
                           || requestPath.equals(String.format("/v1/contingency-lists/contingency-infos/export?networkUuid=%s&ids=%s", NETWORK_UUID, VERY_LARGE_LIST_NAME))) {
                    return new MockResponse(HttpStatus.OK.value(), Headers.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE), veryLargeJsonExpected);
                } else if (requestPath.equals(String.format("/v1/contingency-lists/contingency-infos/export?networkUuid=%s&ids=%s&ids=%s", NETWORK_UUID, LIST_NAME, LIST_NAME_VARIANT))) {
                    return new MockResponse(HttpStatus.OK.value(), Headers.of(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE), jsonExpectedForList);
                } else {
                    return new MockResponse.Builder().code(HttpStatus.NOT_FOUND.value()).body("Path not supported: " + request.getPath()).build();
                }
            }
        };

        server.setDispatcher(dispatcher);

        // Ask the server for its URL. You'll need this to make HTTP requests.
        HttpUrl baseHttpUrl = server.url("");

        return baseHttpUrl.toString().substring(0, baseHttpUrl.toString().length() - 1);
    }

    private static List<ContingencyInfos> createVeryLargeList() {
        return IntStream.range(0, DATA_BUFFER_LIMIT).mapToObj(i -> new ContingencyInfos(new Contingency("l" + i, new BranchContingency("l" + i)))).collect(Collectors.toList());
    }

    @Test
    void test() {
        List<ContingencyInfos> list = actionsService.getContingencyList(List.of(LIST_NAME), UUID.fromString(NETWORK_UUID), null);
        list.forEach(contingencyInfos -> assertArrayEquals(List.of(WRONG_ID).toArray(new Object[0]), contingencyInfos.getNotFoundElements().toArray(new String[0])));
        assertEquals(Stream.of(CONTINGENCY).map(ContingencyInfos::getContingency).toList(), list.stream().map(ContingencyInfos::getContingency).collect(Collectors.toList()));
        list = actionsService.getContingencyList(List.of(LIST_NAME), UUID.fromString(NETWORK_UUID), VARIANT_ID);
        assertEquals(Stream.of(CONTINGENCY_VARIANT).map(ContingencyInfos::getContingency).toList(), list.stream().map(ContingencyInfos::getContingency).collect(Collectors.toList()));
    }

    @Test
    void testVeryLargeList() {
        // DataBufferLimitException should not be thrown with this message : "Exceeded limit on max bytes to buffer : DATA_BUFFER_LIMIT"
        List<ContingencyInfos> list = actionsService.getContingencyList(List.of(VERY_LARGE_LIST_NAME), UUID.fromString(NETWORK_UUID), null);
        list.forEach(contingencyInfos -> assertArrayEquals(List.of().toArray(new Object[0]), contingencyInfos.getNotFoundElements().toArray(new String[0])));
        assertEquals(createVeryLargeList().stream().map(ContingencyInfos::getContingency).collect(Collectors.toList()), list.stream().map(ContingencyInfos::getContingency).collect(Collectors.toList()));
        list = actionsService.getContingencyList(List.of(VERY_LARGE_LIST_NAME), UUID.fromString(NETWORK_UUID), VARIANT_ID);
        assertEquals(createVeryLargeList().stream().map(ContingencyInfos::getContingency).collect(Collectors.toList()), list.stream().map(ContingencyInfos::getContingency).collect(Collectors.toList()));
    }

    @Test
    void testGetContingenciesByListOfIds() {
        List<ContingencyInfos> list = actionsService.getContingencyList(List.of(LIST_NAME, LIST_NAME_VARIANT), UUID.fromString(NETWORK_UUID), null);
        assertEquals(Stream.of(CONTINGENCY, CONTINGENCY_VARIANT).map(ContingencyInfos::getContingency).toList(), list.stream().map(ContingencyInfos::getContingency).collect(Collectors.toList()));
    }
}
