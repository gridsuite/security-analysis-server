/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.powsybl.commons.report.ReportNode;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.iidm.network.VariantManagerConstants;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.client.NetworkStoreService;
import com.powsybl.network.store.client.PreloadingStrategy;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.ws.commons.computation.service.ReportService;
import com.powsybl.ws.commons.computation.service.UuidGeneratorService;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.*;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.gridsuite.securityanalysis.server.repositories.specifications.SpecificationUtils;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisResultService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.data.domain.Sort;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.vladmihalcea.sql.SQLStatementCountValidator.assertSelectCount;
import static com.vladmihalcea.sql.SQLStatementCountValidator.reset;
import static org.assertj.core.api.Assertions.assertThat;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.doNothing;

/**
 * @author Anis Touri <anis.touri at rte-france.com>
 */
@SpringBootTest // would be better with @DataJpaTest but does not work here
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // improve tests speed as we only read DB
class FindPreContingencyLimitViolationTest {

    private static final UUID NETWORK_UUID = UUID.fromString("7928181c-7977-4592-ba19-88027e4254e4");
    private static final UUID RESULT_UUID = UUID.fromString("0c8de370-3e6c-4d72-b292-d355a97e0d5d");

    @Autowired
    private SecurityAnalysisResultRepository securityAnalysisResultRepository;

    private SecurityAnalysisResultEntity resultEntity;

    @Autowired
    private SecurityAnalysisResultService securityAnalysisResultService;

    @MockBean
    private NetworkStoreService networkStoreService;
    @MockBean
    private UuidGeneratorService uuidGeneratorService;
    @MockBean
    private ReportService reportService;

    @BeforeAll
    void setUp() {
        WireMockServer wireMockServer = new WireMockServer(wireMockConfig().dynamicPort());
        wireMockServer.start();
        MockitoAnnotations.initMocks(this);

        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_1_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_2_ID);
        network.getVariantManager().cloneVariant(VariantManagerConstants.INITIAL_VARIANT_ID, VARIANT_3_ID);

        given(networkStoreService.getNetwork(NETWORK_UUID, PreloadingStrategy.ALL_COLLECTIONS_NEEDED_FOR_BUS_VIEW)).willReturn(network);

        // UUID service mocking to always generate the same result UUID
        given(uuidGeneratorService.generate()).willReturn(RESULT_UUID);

        doNothing().when(reportService).sendReport(any(UUID.class), any(ReportNode.class));

        resultEntity = SecurityAnalysisResultEntity.toEntity(network, UUID.randomUUID(), PRECONTINGENCY_RESULT, SecurityAnalysisStatus.CONVERGED);
        securityAnalysisResultRepository.save(resultEntity);
    }

    @AfterAll
    void tearDown() {
        securityAnalysisResultRepository.deleteAll();
    }

    @ParameterizedTest
    @MethodSource({
        "provideSortOnly",
        "provideParentFilter",
        "provideChildFilter",
        "provideEachColumnFilter",
        "provideChildFilterWithTolerance"
    })
    void findFilteredPrecontingencyLimitViolationResultsTest(List<ResourceFilterDTO> filters, Sort sort, List<PreContingencyLimitViolationResultDTO> expectedResult, Integer expectedSelectCount) {
        reset();
        List<PreContingencyLimitViolationResultDTO> preContingencyLimitViolation = securityAnalysisResultService.findNResult(resultEntity.getId(), filters, sort);

        // assert subject ids to check parent filters
        assertThat(preContingencyLimitViolation).extracting(SubjectLimitViolationEntity.Fields.subjectId)
            .containsExactlyElementsOf(
                expectedResult.stream().map(PreContingencyLimitViolationResultDTO::getSubjectId).toList()
        );

        // assert location ids
        assertThat(preContingencyLimitViolation).extracting(PreContingencyLimitViolationResultDTO.Fields.limitViolation + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.locationId)
                .containsExactlyElementsOf(
                        expectedResult.stream().map(preContingencyLimitViolationResultDTO -> preContingencyLimitViolationResultDTO.getLimitViolation().getLocationId()).toList()
        );

        assertSelectCount(expectedSelectCount);
    }

    private static Stream<Arguments> provideSortOnly() {
        return Stream.of(
                Arguments.of(List.of(), Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId), RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).toList(), 2),
                Arguments.of(List.of(), Sort.by(Sort.Direction.DESC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId), RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId).reversed()).toList(), 2)
        );
    }

    private static Stream<Arguments> provideParentFilter() {
        return Stream.of(
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId)), Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
                        RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().contains("3")).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId)), Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
                        RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().startsWith("l")).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", AbstractLimitViolationEntity.Fields.locationId)), Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.locationId),
                        RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().startsWith("3")).toList(), 2)
        );
    }

    private static Stream<Arguments> provideChildFilter() {
        return Stream.of(
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l6", AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId)), Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
                        getResultPreContingencyWithNestedFilter(p -> p.getSubjectId().contains("l6"))
                                .stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.LESS_THAN_OR_EQUAL, "390", AbstractLimitViolationEntity.Fields.limit)), Sort.by(Sort.Direction.ASC, "limit"),
                        getResultPreContingencyWithNestedFilter(p -> p.getLimitViolation().getLimit() <= 390)
                                .stream().sorted(Comparator.comparing(x -> x.getLimitViolation().getLimit())).toList(), 2)
        );
    }

    private static Stream<Arguments> provideChildFilterWithTolerance() {
        return Stream.of(
                Arguments.of(List.of(
                                new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.NOT_EQUAL, "11.02425", AbstractLimitViolationEntity.Fields.value),
                                new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.LESS_THAN_OR_EQUAL, "10.51243", AbstractLimitViolationEntity.Fields.limit),
                                new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.GREATER_THAN_OR_EQUAL, "0.999999", AbstractLimitViolationEntity.Fields.limitReduction)
                        ), Sort.by(Sort.Direction.ASC, "limit"),
                        getResultPreContingencyWithNestedFilter(p -> p.getLimitViolation().getLimit() <= 10.51243)
                                .stream().sorted(Comparator.comparing(x -> x.getLimitViolation().getLimit())).toList(), 2)
        );
    }

    private static Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "ONE", AbstractLimitViolationEntity.Fields.side)), Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
                        getResultPreContingencyWithNestedFilter(c -> c.getLimitViolation().getSide() != null && c.getLimitViolation().getSide().equals(ThreeSides.ONE)).stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "l5_name", AbstractLimitViolationEntity.Fields.limitName)), Sort.by(Sort.Direction.ASC, AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
                        getResultConstraintsWithNestedFilter(c -> c.getLimitViolation().getLimitName().equals("l5_name")).stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList(), 2)
        );
    }
}
