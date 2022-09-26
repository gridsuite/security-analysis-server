/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import org.gridsuite.securityanalysis.server.service.ActionsService;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisExecutionService;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.FluxExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.config.EnableWebFlux;
import reactor.core.publisher.Flux;

import java.io.IOException;
import java.util.UUID;

import static com.powsybl.network.store.model.NetworkStoreApi.VERSION;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;

@RunWith(SpringRunner.class)
@AutoConfigureWebTestClient
@EnableWebFlux
@SpringBootTest
public class SecurityAnalysisControllerErrorTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final String ERROR_MESSAGE = "error test case no getLocalComputationManager";

    @Autowired
    private WebTestClient webTestClient;

    @MockBean
    private NetworkStoreService networkStoreService;

    @MockBean
    private ActionsService actionsService;

    @MockBean
    private SecurityAnalysisExecutionService executionService;

    @Before
    public void setUp() throws IOException {
        // mock to fail while asking a LocalComputationManager
        given(executionService.getLocalComputationManager()).willThrow(new IOException(ERROR_MESSAGE));
        // mock minimal data to request a SA run
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.COLLECTION)).willReturn(network);
        given(actionsService.getContingencyList(CONTINGENCY_LIST_NAME, NETWORK_UUID, null)) // initial variant
                .willReturn(Flux.fromIterable(SecurityAnalysisProviderMock.CONTINGENCIES));
    }

    @Test
    public void runErrorCaseNoLocalComputationTest() {
        WebTestClient.ResponseSpec res = webTestClient.post()
                .uri("/" + VERSION + "/networks/" + NETWORK_UUID + "/run?contingencyListName=" + CONTINGENCY_LIST_NAME)
                .exchange()
                .expectStatus().is5xxServerError();  // no LocalComputationManager => 500 failure

        FluxExchangeResult<String> result = res.returnResult(String.class);
        assertTrue(result.toString().contains(ERROR_MESSAGE));
    }
}
