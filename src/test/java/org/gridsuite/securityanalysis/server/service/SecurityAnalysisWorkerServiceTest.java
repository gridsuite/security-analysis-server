/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import org.gridsuite.computation.dto.ReportInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersDTO;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class SecurityAnalysisWorkerServiceTest {

    public static final String WORKING_VARIANT_1 = "myVariant1";
    public static final String WORKING_VARIANT_2 = "myVariant2";
    @Mock private ActionsService actionsService;
    @Mock private SecurityAnalysisRunnerSupplier runnerSupplier;

    private SecurityAnalysisWorkerService workerService;

    private SecurityAnalysisRunContext buildRunContext(String provider, String variantId, Network network) {
        SecurityAnalysisRunContext ctx = new SecurityAnalysisRunContext(
                UUID.randomUUID(),
                variantId,
                null,
                provider,
                SecurityAnalysisParametersDTO.builder()
                        .securityAnalysisParameters(new com.powsybl.security.SecurityAnalysisParameters())
                        .contingencyListUuids(List.of())
                        .limitReductions(List.of())
                        .build(),
                new ReportInfos(null, null, null),
                "testUser"
        );
        ctx.setNetwork(network);
        return ctx;
    }

    @BeforeEach
    void setUp() {
        workerService = new SecurityAnalysisWorkerService(
                null,
                actionsService,
                null,
                null,
                null,
                runnerSupplier,
                null,
                null,
                null,
                null,
                null
        );
    }

    @Test
    void copyNetworkOpenLoadFlowWithInitialVariant() {
        Network original = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        SecurityAnalysisRunContext ctx = buildRunContext("OpenLoadFlow", null, original);

        String workingVariant = original.getVariantManager().getWorkingVariantId();

        workerService.copyNetwork(ctx);

        Network result = ctx.getInMemoryNetwork();

        assertThat(result).isNotSameAs(original);
        assertThat(result.getId()).isEqualTo(original.getId());
        assertThat(result.getVariantManager().getWorkingVariantId()).isEqualTo(workingVariant);
    }

    @Test
    void copyNetworkWithCustomVariant() {
        Network original = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        original.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, WORKING_VARIANT_1);
        original.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, WORKING_VARIANT_2);
        original.getVariantManager().setWorkingVariant(WORKING_VARIANT_1);

        String workingVariant = original.getVariantManager().getWorkingVariantId();

        SecurityAnalysisRunContext ctx = buildRunContext("OpenLoadFlow", WORKING_VARIANT_2, original);

        workerService.copyNetwork(ctx);

        Network result = ctx.getInMemoryNetwork();

        assertThat(result.getVariantManager().getVariantIds()).contains(WORKING_VARIANT_2);
        assertThat(original.getVariantManager().getWorkingVariantId()).isEqualTo(workingVariant);
    }
}
