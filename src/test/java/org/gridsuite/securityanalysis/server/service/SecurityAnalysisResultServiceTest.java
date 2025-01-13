/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.ws.commons.computation.service.ReportService;
import com.powsybl.ws.commons.computation.service.UuidGeneratorService;
import com.vladmihalcea.sql.SQLStatementCountValidator;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import java.util.UUID;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.gridsuite.securityanalysis.server.util.DatabaseQueryUtils.assertRequestsCount;
import static org.mockito.BDDMockito.given;

/**
 * @author Florent MILLOT <florent.millot@rte-france.com>
 */
@SpringBootTest
class SecurityAnalysisResultServiceTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5d");
    @Autowired
    private SecurityAnalysisResultService securityAnalysisResultService;

    @MockBean
    private NetworkStoreService networkStoreService;
    @MockBean
    private UuidGeneratorService uuidGeneratorService;

    @MockBean
    private ReportService reportService;

    @Test
    void deleteResultPerfTest() {
        WireMockServer wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
        wireMockServer.start();
        MockitoAnnotations.initMocks(this);

        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());

        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.ALL_COLLECTIONS_NEEDED_FOR_BUS_VIEW)).willReturn(network);

        // UUID service mocking to always generate the same result UUID
        given(uuidGeneratorService.generate()).willReturn(RESULT_UUID);
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(network, resultUuid, RESULT, SecurityAnalysisStatus.CONVERGED);
        SQLStatementCountValidator.reset();

        securityAnalysisResultService.delete(resultUuid);

        // 6 manual delete
        // 1 manual select to get the contingencyUuids, and 4 select at the end for the last delete when applying the cascade
        assertRequestsCount(5, 0, 0, 6);
    }
}
