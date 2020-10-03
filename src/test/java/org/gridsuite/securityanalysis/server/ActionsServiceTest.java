/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import okhttp3.HttpUrl;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.ContextHierarchy;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@RunWith(SpringRunner.class)
@EnableWebFlux
@ContextHierarchy({@ContextConfiguration(classes = {SecurityAnalysisApplication.class, ActionsService.class})})
public class ActionsServiceTest extends AbstractEmbeddedCassandraSetup {

    private static final String NETWORK_UUID = "7928181c-7977-4592-ba19-88027e4254e4";

    private static final String LIST_NAME = "myList";

    private static final Contingency CONTINGENCY = new Contingency("c1", new BranchContingency("b1"));

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private WebClient.Builder webClientBuilder;

    @Test
    public void test() throws IOException {
        MockWebServer server = new MockWebServer();
        server.start();
        final Dispatcher dispatcher = new Dispatcher() {
            @Override
            public MockResponse dispatch(RecordedRequest request) {
                if (("/" + ActionsService.ACTIONS_API_VERSION + "/contingency-lists/" + LIST_NAME + "/export?networkUuid=" + NETWORK_UUID)
                        .equals(request.getPath())) {
                    try {
                        String json = objectMapper.writeValueAsString(List.of(CONTINGENCY));
                        return new MockResponse()
                                .setResponseCode(200)
                                .setBody(json)
                                .addHeader("Content-Type", "application/json; charset=utf-8");
                    } catch (JsonProcessingException e) {
                        throw new UncheckedIOException(e);
                    }
                }
                return new MockResponse().setResponseCode(404);
            }
        };
        server.setDispatcher(dispatcher);

        // get server base URL
        HttpUrl baseHttpUrl = server.url("");
        String baseUrl = baseHttpUrl.toString().substring(0, baseHttpUrl.toString().length() - 1);

        ActionsService actionsService = new ActionsService(webClientBuilder, baseUrl);

        List<Contingency> list = actionsService.getContingencyList(LIST_NAME, UUID.fromString(NETWORK_UUID)).block();
        assertEquals(List.of(CONTINGENCY), list);

        server.shutdown();
    }
}
