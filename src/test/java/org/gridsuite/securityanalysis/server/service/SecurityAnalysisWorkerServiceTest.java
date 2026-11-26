/**
 * Copyright (c) 2026, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.contingency.Contingency;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import org.gridsuite.computation.dto.ReportInfos;
import org.gridsuite.securityanalysis.server.dto.ContingencyInfos;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisParametersDTO;
import org.gridsuite.securityanalysis.server.error.SecurityAnalysisBusinessErrorCode;
import org.gridsuite.securityanalysis.server.error.SecurityAnalysisException;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisRunnerSupplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecurityAnalysisWorkerServiceTest {

    public static final String WORKING_VARIANT_1 = "myVariant1";
    public static final String WORKING_VARIANT_2 = "myVariant2";
    @Mock private ActionsService actionsService;
    @Mock private SecurityAnalysisRunnerSupplier runnerSupplier;
    private final SecurityAnalysisObserver observer = new SecurityAnalysisObserver(ObservationRegistry.NOOP, new SimpleMeterRegistry());

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
        lenient().when(actionsService.getContingencyList(any(), any(), any()))
                .thenReturn(List.of(new ContingencyInfos(new Contingency("contingency"))));
        workerService = new SecurityAnalysisWorkerService(
                null,
                actionsService,
                null,
                null,
                null,
                runnerSupplier,
                null,
                null,
                observer,
                null,
                null
        );
    }

    @Test
    void testCopyNetworkOnAnotherProvider() {
        Network original = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        SecurityAnalysisRunContext ctx = buildRunContext("Provider", null, original);
        workerService.preRun(ctx);

        assertThat(ctx.getInMemoryNetwork()).isNull();
    }

    @Test
    void copyNetworkOpenLoadFlowWithInitialVariant() {
        Network original = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        SecurityAnalysisRunContext ctx = buildRunContext("OpenLoadFlow", null, original);

        String workingVariant = original.getVariantManager().getWorkingVariantId();

        workerService.preRun(ctx);

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

        workerService.preRun(ctx);

        Network result = ctx.getInMemoryNetwork();

        assertThat(result.getVariantManager().getVariantIds()).contains(WORKING_VARIANT_2);
        assertThat(original.getVariantManager().getWorkingVariantId()).isEqualTo(workingVariant);
    }

    private HttpClientErrorException.NotFound notFoundWithBody(String body) {
        return (HttpClientErrorException.NotFound) HttpClientErrorException.create(
                HttpStatus.NOT_FOUND, "Not Found", new HttpHeaders(), body.getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8);
    }

    @Test
    void preRunThrowsMissingContingencyListWhenActionsServerReportsContingencyListNotFound() {
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        SecurityAnalysisRunContext ctx = buildRunContext("OpenLoadFlow", null, network);
        String body = "{\"server\":\"actions-server\",\"businessErrorCode\":\"actions.contingencyListNotFound\",\"detail\":\"Contingency list 'xxx' not found\"}";
        when(actionsService.getContingencyList(any(), any(), any())).thenThrow(notFoundWithBody(body));

        assertThatThrownBy(() -> workerService.preRun(ctx))
                .isInstanceOf(SecurityAnalysisException.class)
                .extracting(e -> ((SecurityAnalysisException) e).getBusinessErrorCode())
                .isEqualTo(SecurityAnalysisBusinessErrorCode.MISSING_CONTINGENCY_LIST);
    }

    @Test
    void preRunRethrowsOriginalExceptionWhenActionsServerReportsNetworkNotFound() {
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        SecurityAnalysisRunContext ctx = buildRunContext("OpenLoadFlow", null, network);
        String body = "{\"server\":\"actions-server\",\"businessErrorCode\":\"actions.networkNotFound\",\"detail\":\"Network 'xxx' not found\"}";
        HttpClientErrorException.NotFound exception = notFoundWithBody(body);
        when(actionsService.getContingencyList(any(), any(), any())).thenThrow(exception);

        assertThatThrownBy(() -> workerService.preRun(ctx)).isSameAs(exception);
    }

}
