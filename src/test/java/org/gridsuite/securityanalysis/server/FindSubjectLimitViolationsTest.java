/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.powsybl.iidm.network.Network;
import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.iidm.network.test.EurostagTutorialExample1Factory;
import com.powsybl.network.store.iidm.impl.NetworkFactoryImpl;
import com.powsybl.security.LimitViolationType;
import org.gridsuite.computation.dto.ResourceFilterDTO;
import org.gridsuite.computation.error.ComputationException;
import org.gridsuite.computation.utils.SpecificationUtils;
import org.gridsuite.securityanalysis.server.dto.ContingencyLimitViolationDTO;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.dto.SubjectLimitViolationResultDTO;
import org.gridsuite.securityanalysis.server.entities.*;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisResultService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static com.vladmihalcea.sql.SQLStatementCountValidator.assertSelectCount;
import static com.vladmihalcea.sql.SQLStatementCountValidator.reset;
import static org.assertj.core.api.Assertions.assertThat;
import static org.gridsuite.computation.error.ComputationBusinessErrorCode.INVALID_SORT_FORMAT;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
@SpringBootTest // would be better with @DataJpaTest but does not work here
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // improve tests speed as we only read DB
class FindSubjectLimitViolationsTest {
    @Autowired
    private SecurityAnalysisResultRepository securityAnalysisResultRepository;

    private SecurityAnalysisResultEntity resultEntity;

    @Autowired
    private SecurityAnalysisResultService securityAnalysisResultService;

    @Autowired
    private ObjectMapper mapper;

    @BeforeAll
    void setUp() {
        // network store service mocking
        Network network = EurostagTutorialExample1Factory.create(new NetworkFactoryImpl());
        resultEntity = SecurityAnalysisResultEntity.toEntity(network, UUID.randomUUID(), RESULT, SecurityAnalysisStatus.CONVERGED);
        securityAnalysisResultRepository.save(resultEntity);
    }

    @AfterAll
    void tearDown() {
        securityAnalysisResultRepository.deleteAll();
    }

    @ParameterizedTest
    @MethodSource({
        "providePageableAndSortOnly",
        "provideParentFilter",
        "provideChildFilter",
        "provideChildSorting",
        "provideEachColumnFilter"
    })
    void findFilteredSubjectLimitViolationResultsTest(List<ResourceFilterDTO> filters, Pageable pageable, List<SubjectLimitViolationResultDTO> expectedResult, Integer expectedSelectCount) throws JsonProcessingException {
        reset();
        Page<SubjectLimitViolationResultDTO> subjectLimitViolationPage = securityAnalysisResultService.findNmKConstraintsResultPaged(resultEntity.getId(), null, null, mapper.writeValueAsString(filters), null, pageable);

        // assert subject ids to check parent filters
        assertThat(subjectLimitViolationPage.getContent()).extracting("subjectId").containsExactlyElementsOf(expectedResult.stream().map(SubjectLimitViolationResultDTO::getSubjectId).toList());
        assertThat(subjectLimitViolationPage.getContent().stream()
                .map(lm -> lm.getContingencies().stream().map(c -> c.getLimitViolation().getLocationId()).toList()))
                .containsExactlyElementsOf(expectedResult.stream().map(slm -> slm.getContingencies().stream().map(FindSubjectLimitViolationsTest::getContingencyLimitViolationDTOLocationId).toList()).toList());
        // assert limit violation contingency ids to check nested filters
        assertThat(subjectLimitViolationPage.getContent().stream()
            .map(lm -> lm.getContingencies().stream().map(c -> c.getContingency().getContingencyId()).toList()))
            .containsExactlyElementsOf(expectedResult.stream().map(c -> c.getContingencies().stream().map(FindSubjectLimitViolationsTest::getContingencyLimitViolationDTOContingencyId).toList()).toList());

        // select count check to prevent potential n+1 problems
        // 2 -> assertResultExists ; parent UUIDs ; empty parents, no count or children request
        // 5 -> assertResultExists ; parent UUIDs + parents + children + contingencyElements ; no count (number of element < page size)
        // 6 -> assertResultExists ; parent UUIDs + count + parents + children + contingencyElements
        assertSelectCount(expectedSelectCount);
    }

    @ParameterizedTest
    @MethodSource({
        "provideForbiddenSort",
        "provideForbiddenFilter"
    })
    void testSortAndFilterErrors(List<ResourceFilterDTO> filters, Pageable pageable, Exception expectedException) {
        Exception exception = assertThrows(expectedException.getClass(), () -> securityAnalysisResultService.findNmKConstraintsResultPaged(resultEntity.getId(), null, null, mapper.writeValueAsString(filters), null, pageable));
        assertEquals(expectedException.getMessage(), exception.getMessage());
    }

    private static Stream<Arguments> providePageableAndSortOnly() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList(), 5),
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.DESC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId).reversed()).toList(), 5),
            Arguments.of(List.of(), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList().subList(0, 2), 6),
            Arguments.of(List.of(), PageRequest.of(1, 2, Sort.by(Sort.Direction.ASC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList().subList(2, Math.min(RESULT_CONSTRAINTS.size(), 4)), 6)
        );
    }

    private static Stream<Arguments> provideParentFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", SubjectLimitViolationEntity.Fields.subjectId)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")),
                RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().contains("3")).toList(), 5),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", SubjectLimitViolationEntity.Fields.subjectId)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")),
                RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().startsWith("l")).toList(), 5),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", SubjectLimitViolationEntity.Fields.subjectId)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")),
                RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().startsWith("3")).toList(), 2)
        );
    }

    private static Stream<Arguments> provideChildFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "2", SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.contingency + SpecificationUtils.FIELD_SEPARATOR + ContingencyEntity.Fields.contingencyId)), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, "subjectId")),
                getResultConstraintsWithNestedFilter(c -> c.getContingency().getContingencyId().contains("2"))
                    .stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList()
                    .subList(0, 2), 6), // find 1st page of size 2 of contingencies, filtered by SubjectId
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "CURRENT", SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType)), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, "subjectId")),
                getResultConstraintsWithNestedFilter(c -> c.getLimitViolation().getLimitType().equals(LimitViolationType.CURRENT))
                    .stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList()
                    .subList(0, 2), 6)
        );
    }

    private static Stream<Arguments> provideChildSorting() {
        return Stream.of(
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.contingency + SpecificationUtils.FIELD_SEPARATOR + ContingencyEntity.Fields.contingencyId),
                Comparator.comparing(c -> c.getContingency().getContingencyId(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.contingency + SpecificationUtils.FIELD_SEPARATOR + ContingencyEntity.Fields.status),
                Comparator.comparing(c -> c.getContingency().getStatus(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limit),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLimit(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitName),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLimitName(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLimitType(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.value),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getValue(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.loading),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLoading(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.acceptableDuration),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getAcceptableDuration(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getSide(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            // default sorting
            buildArgumentsForChildrenSorting(
                Sort.unsorted(),
                Comparator.comparing(c -> c.getContingency().getContingencyId(), Comparator.nullsLast(Comparator.naturalOrder()))
            )
        );
    }

    private static Arguments buildArgumentsForChildrenSorting(Sort childrenSort, Comparator<ContingencyLimitViolationDTO> childrenComparator) {
        return Arguments.of(
            List.of(),
            PageRequest.of(0, 4,
                Sort.by(Sort.Direction.ASC, SubjectLimitViolationEntity.Fields.subjectId)
                    .and(childrenSort)),
            getResultConstraintsSorted(
                childrenComparator,
                Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId))
                .subList(0, 4), 6);
    }

    private static Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "CO", SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.contingency + SpecificationUtils.FIELD_SEPARATOR + ContingencyEntity.Fields.status)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")),
                getResultConstraintsWithNestedFilter(c -> c.getContingency().getStatus().contains("CO")).stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList(), 5),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "ONE", SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")),
                getResultConstraintsWithNestedFilter(c -> c.getLimitViolation().getSide() != null && c.getLimitViolation().getSide().equals(ThreeSides.ONE)).stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList(), 5),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "l6_name", SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitName)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")),
                getResultConstraintsWithNestedFilter(c -> c.getLimitViolation().getLimitName().equals("l6_name")).stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList(), 5)
        );
    }

    private static Stream<Arguments> provideForbiddenSort() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")), new ComputationException(INVALID_SORT_FORMAT, "Invalid sort format")),
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.DESC, "side")), new ComputationException(INVALID_SORT_FORMAT, "Invalid sort format"))
        );
    }

    private static Stream<Arguments> provideForbiddenFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.CONTAINS, 3, SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limit)), PageRequest.of(0, 30), new IllegalArgumentException("The filter type CONTAINS is not supported with the data type NUMBER"))
        );
    }

    private static String getContingencyLimitViolationDTOContingencyId(ContingencyLimitViolationDTO contingencyLimitViolationDTO) {
        return contingencyLimitViolationDTO.getContingency().getContingencyId();
    }

    private static String getContingencyLimitViolationDTOLocationId(ContingencyLimitViolationDTO contingencyLimitViolationDTO) {
        return contingencyLimitViolationDTO.getLimitViolation().getLocationId();
    }
}
