/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.contingency.BranchContingency;
import com.powsybl.contingency.Contingency;
import com.powsybl.contingency.violations.LimitViolation;
import com.powsybl.contingency.violations.LimitViolationType;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.TwoSides;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.LimitViolationsResult;
import com.powsybl.security.PostContingencyComputationStatus;
import com.powsybl.security.SecurityAnalysisResult;
import com.powsybl.security.results.ConnectivityResult;
import com.powsybl.security.results.NetworkResult;
import com.powsybl.security.results.PostContingencyResult;
import com.vladmihalcea.sql.SQLStatementCountValidator;
import org.gridsuite.computation.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.dto.ContingencyResultDTO;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.dto.SubjectLimitViolationDTO;
import org.gridsuite.securityanalysis.server.dto.SubjectLimitViolationResultDTO;
import org.gridsuite.securityanalysis.server.repositories.specifications.ContingencySpecificationBuilder;
import org.gridsuite.securityanalysis.server.repositories.specifications.SubjectLimitViolationSpecificationBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.gridsuite.securityanalysis.server.util.DatabaseQueryUtils.assertRequestsCount;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

/**
 * @author Florent MILLOT <florent.millot@rte-france.com>
 */
@SpringBootTest
class SecurityAnalysisResultServiceTest {
    @Autowired
    private SecurityAnalysisResultService securityAnalysisResultService;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoSpyBean
    private ContingencySpecificationBuilder contingencySpecificationBuilder;

    @MockitoSpyBean
    private SubjectLimitViolationSpecificationBuilder subjectLimitViolationSpecificationBuilder;

    @Captor
    ArgumentCaptor<List<ResourceFilterDTO>> filtersCaptor;

    @Test
    void deleteResultPerfTest() {
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(network, resultUuid, RESULT, SecurityAnalysisStatus.CONVERGED);
        SQLStatementCountValidator.reset();

        securityAnalysisResultService.delete(resultUuid);

        // 6 manual delete
        // 1 manual select to get the contingencyUuids, and 4 select at the end for the last delete when applying the cascade
        assertRequestsCount(5, 0, 0, 6);
    }

    @Test
    void insertResultWithoutNetworkTest() {
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(null, resultUuid, RESULT, SecurityAnalysisStatus.CONVERGED);
        securityAnalysisResultService.assertResultExists(resultUuid);

        List<ContingencyResultDTO> contingencyResults = securityAnalysisResultService.findNmKContingenciesResult(resultUuid);
        assertEquals(RESULT.getPostContingencyResults().size(), contingencyResults.size());
        // check fields based on network are actually nullish
        contingencyResults.forEach(this::checkFieldBasedOnNetworkAreNullish);
    }

    @Test
    void findNmKContingenciesPagedNormalizesWorstSideFilter() throws Exception {
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(null, resultUuid, createSecurityAnalysisResultWithTwoSides(),
            SecurityAnalysisStatus.CONVERGED);

        Page<ContingencyResultDTO> page = securityAnalysisResultService.findNmKContingenciesPaged(
            resultUuid,
            null,
            null,
            createWorstSideFilterAsString(),
            null,
            PageRequest.of(0, 10)
        );

        assertThat(captureContingencyFilters(resultUuid))
            .isNotEmpty()
            .allSatisfy(this::assertWorstSideFilterIsNormalized);

        assertThat(page.getContent()).hasSize(1);
        assertThat(page.getContent().getFirst().getSubjectLimitViolations())
            .singleElement()
            .satisfies(subjectLimitViolation -> {
                assertThat(subjectLimitViolation.getLimitViolation().getValue()).isEqualTo(130.);
                assertThat(subjectLimitViolation.getLimitViolation().getSide()).isEqualTo(TwoSides.TWO.toThreeSides());
            });
    }

    @Test
    void findNmKConstraintsResultPagedNormalizesWorstSideFilter() throws Exception {
        UUID resultUuid = UUID.randomUUID();
        securityAnalysisResultService.insert(null, resultUuid, createSecurityAnalysisResultWithTwoSides(),
            SecurityAnalysisStatus.CONVERGED);

        Page<SubjectLimitViolationResultDTO> page = securityAnalysisResultService.findNmKConstraintsResultPaged(
            resultUuid,
            null,
            null,
            createWorstSideFilterAsString(),
            null,
            PageRequest.of(0, 10)
        );

        assertThat(captureSubjectLimitViolationFilters(resultUuid))
            .isNotEmpty()
            .allSatisfy(this::assertWorstSideFilterIsNormalized);

        assertThat(page.getContent()).hasSize(1);
        assertThat(page.getContent().getFirst().getContingencies())
            .singleElement()
            .satisfies(contingency -> {
                assertThat(contingency.getLimitViolation().getValue()).isEqualTo(130.);
                assertThat(contingency.getLimitViolation().getSide()).isEqualTo(TwoSides.TWO.toThreeSides());
            });
    }

    @SuppressWarnings("java:S5841") // some limitViolation could be empty, which will make allSatisfy pass automatically - this behaviour is intended
    private void checkFieldBasedOnNetworkAreNullish(ContingencyResultDTO contingencyResult) {
        assertThat(contingencyResult.getSubjectLimitViolations())
            .extracting(SubjectLimitViolationDTO::getLimitViolation)
            .allSatisfy(lv ->
                assertThat(lv)
                    .satisfies(v -> assertThat(v.getPatlLimit()).isNull())
                    .satisfies(v -> assertThat(v.getPatlLoading()).isNull())
                    .satisfies(v -> assertThat(v.getNextLimitName()).isNull())
                    .satisfies(v -> assertThat(v.getLocationId()).isNull())
                    .satisfies(v -> assertThat(v.getAcceptableDuration()).isNull())
            );
    }

    private SecurityAnalysisResult createSecurityAnalysisResultWithTwoSides() {
        String subjectId = "branchId";
        return new SecurityAnalysisResult(
            new LimitViolationsResult(List.of()),
            LoadFlowResult.ComponentResult.Status.CONVERGED,
            List.of(new PostContingencyResult(
                new Contingency("contingencyId", new BranchContingency(subjectId)),
                PostContingencyComputationStatus.CONVERGED,
                new LimitViolationsResult(List.of(
                    new LimitViolation(subjectId, LimitViolationType.CURRENT, "limitName", 60, 100, 1, 110,
                        TwoSides.ONE),
                    new LimitViolation(subjectId, LimitViolationType.CURRENT, "limitName", 60, 100, 1, 130,
                        TwoSides.TWO)
                )),
                NetworkResult.empty(),
                ConnectivityResult.empty(),
                1.0
            ))
        );
    }

    private String createWorstSideFilterAsString() throws Exception {
        return objectMapper.writeValueAsString(List.of(new ResourceFilterDTO(
            ResourceFilterDTO.DataType.TEXT,
            ResourceFilterDTO.Type.EQUALS,
            List.of("worst"),
            "contingencyLimitViolations.side"
        )));
    }

    private static ResourceFilterDTO createExpectedWorstSideFilter() {
        return new ResourceFilterDTO(
            ResourceFilterDTO.DataType.BOOLEAN,
            ResourceFilterDTO.Type.EQUALS,
            true,
            "contingencyLimitViolations.isWorstSide"
        );
    }

    private List<List<ResourceFilterDTO>> captureContingencyFilters(UUID resultUuid) {
        verify(contingencySpecificationBuilder).buildSpecification(eq(resultUuid), filtersCaptor.capture());
        verify(contingencySpecificationBuilder).buildLimitViolationsSpecification(anyList(), filtersCaptor.capture());

        return filtersCaptor.getAllValues();
    }

    private List<List<ResourceFilterDTO>> captureSubjectLimitViolationFilters(UUID resultUuid) {
        verify(subjectLimitViolationSpecificationBuilder).buildSpecification(eq(resultUuid), filtersCaptor.capture());
        verify(subjectLimitViolationSpecificationBuilder).buildLimitViolationsSpecification(anyList(), filtersCaptor.capture());

        return filtersCaptor.getAllValues();
    }

    private void assertWorstSideFilterIsNormalized(List<ResourceFilterDTO> filters) {
        assertThat(filters).containsExactly(createExpectedWorstSideFilter());
    }

    @AfterEach
    void tearDown() {
        securityAnalysisResultService.deleteAll();
    }
}
