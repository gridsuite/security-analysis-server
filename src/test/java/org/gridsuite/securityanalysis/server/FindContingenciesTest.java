/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.security.LimitViolationType;
import com.powsybl.ws.commons.computation.dto.ResourceFilterDTO;
import com.powsybl.ws.commons.computation.ComputationException;
import com.powsybl.ws.commons.computation.utils.specification.SpecificationUtils;
import org.gridsuite.securityanalysis.server.dto.ContingencyResultDTO;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.dto.SubjectLimitViolationDTO;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
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
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
@SpringBootTest // would be better with @DataJpaTest but does not work here
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // improve tests speed as we only read DB
class FindContingenciesTest {
    @Autowired
    private SecurityAnalysisResultRepository securityAnalysisResultRepository;

    private SecurityAnalysisResultEntity resultEntity;

    @Autowired
    private SecurityAnalysisResultService securityAnalysisResultService;

    @BeforeAll
    void setUp() {
        resultEntity = SecurityAnalysisResultEntity.toEntity(UUID.randomUUID(), RESULT, SecurityAnalysisStatus.CONVERGED);
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
        "provideEachColumnFilter",
        "provideCollectionOfFilters",
        "provideEdgeCasesFilters"
    })
    void findFilteredContingencyResultsTest(List<ResourceFilterDTO> filters, Pageable pageable, List<ContingencyResultDTO> expectedResult, Integer expectedSelectCount) {
        reset();
        Page<ContingencyEntity> contingenciesPage = securityAnalysisResultService.findContingenciesPage(resultEntity.getId(), filters, pageable);

        // assert contingency ids to check parent filters
        assertThat(contingenciesPage.getContent()).extracting(ContingencyEntity.Fields.contingencyId).containsExactlyElementsOf(expectedResult.stream().map(c -> c.getContingency().getContingencyId()).toList());
        // assert subject limit violation ids to check nested filters
        assertThat(contingenciesPage.getContent().stream()
            .map(ContingencyResultDTO::toDto) // call toDTO method to check if it provokes any more requests
            .map(c -> c.getSubjectLimitViolations().stream().map(SubjectLimitViolationDTO::getSubjectId).toList()))
            .containsExactlyElementsOf(expectedResult.stream().map(c -> c.getSubjectLimitViolations().stream().map(SubjectLimitViolationDTO::getSubjectId).toList()).toList());

        // select count check to prevent potential n+1 problems
        // 1 -> parent UUIDs ; empty parents, no count or children request
        // 4 -> parent UUIDs + parents + children + contingencyElements ; no count (number of element < page size)
        // 5 -> parent UUIDs + count + parents + children + contingencyElements
        assertSelectCount(expectedSelectCount);
    }

    @ParameterizedTest
    @MethodSource({
        "provideForbiddenSort",
        "provideForbiddenFilter"
    })
    void testSortAndFilterErrors(List<ResourceFilterDTO> filters, Pageable pageable, Exception expectedException) {
        Exception exception = assertThrows(expectedException.getClass(), () -> securityAnalysisResultService.findContingenciesPage(resultEntity.getId(), filters, pageable));
        assertEquals(expectedException.getMessage(), exception.getMessage());
    }

    private static Stream<Arguments> providePageableAndSortOnly() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 5, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList().subList(0, 5), 5),
            Arguments.of(List.of(), PageRequest.of(0, 5, Sort.by(Sort.Direction.DESC, ContingencyEntity.Fields.contingencyId)), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId).reversed()).toList().subList(0, 5), 5)
        );
    }

    private static Stream<Arguments> provideParentFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", ContingencyEntity.Fields.contingencyId)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().contains("3")).sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", ContingencyEntity.Fields.contingencyId)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("l")).sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", ContingencyEntity.Fields.contingencyId)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("3")).sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 1)
        );
    }

    private static Stream<Arguments> provideChildFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l6", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId)), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                getResultContingenciesWithNestedFilter(lm -> lm.getSubjectId().equals("l6"))
                    .stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList()
                    .subList(0, 2), 5), // find 1st page of size 2 of contingencies, filtered by SubjectId
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "CURRENT", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType)), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getLimitType().equals(LimitViolationType.CURRENT))
                    .stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList()
                    .subList(0, 2), 5),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "not_found", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId)), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                List.of(), 1) // filter by not found limit_violation
        );
    }

    private static Stream<Arguments> provideChildSorting() {
        return Stream.of(
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
                Comparator.comparing(SubjectLimitViolationDTO::getSubjectId, Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limit),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLimit(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitName),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLimitName(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLimitType(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.value),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getValue(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.loading),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getLoading(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.acceptableDuration),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getAcceptableDuration(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            buildArgumentsForChildrenSorting(
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side),
                Comparator.comparing(subjectLimitViolationDTO -> subjectLimitViolationDTO.getLimitViolation().getSide(), Comparator.nullsLast(Comparator.naturalOrder()))
            ),
            // default sorting
            buildArgumentsForChildrenSorting(
                Sort.unsorted(),
                Comparator.comparing(SubjectLimitViolationDTO::getSubjectId, Comparator.nullsLast(Comparator.naturalOrder()))
            )
        );
    }

    private static Arguments buildArgumentsForChildrenSorting(Sort childrenSort, Comparator<SubjectLimitViolationDTO> childrenComparator) {
        return Arguments.of(
            List.of(),
            PageRequest.of(0, 5,
                Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)
                    .and(childrenSort)),
            getResultContingenciesSorted(
                childrenComparator,
                Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId))
                .subList(0, 5), 5);
    }

    private static Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "CO", ContingencyEntity.Fields.status)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getStatus().contains("CO")).sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "ONE", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getSide() != null && lm.getLimitViolation().getSide().equals(ThreeSides.ONE)).stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "l6_name", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitName)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getLimitName().equals("l6_name")).stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 4)
        );
    }

    private static Stream<Arguments> provideCollectionOfFilters() {
        return Stream.of(
            Arguments.of(
                List.of(
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l", ContingencyEntity.Fields.contingencyId),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", ContingencyEntity.Fields.contingencyId),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "CONVERGED", ContingencyEntity.Fields.status)
                ),
                PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().contains("l") && c.getContingency().getContingencyId().contains("3") && c.getContingency().getStatus().equals("CONVERGED")).sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(),
                4), // list of parent filters
            Arguments.of(
                List.of(
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l6", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.subjectLimitViolation + SpecificationUtils.FIELD_SEPARATOR + SubjectLimitViolationEntity.Fields.subjectId),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "CURRENT", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType)
                ),
                PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                getResultContingenciesWithNestedFilter(c -> c.getSubjectId().equals("l6") && c.getLimitViolation().getLimitType().equals(LimitViolationType.CURRENT)).stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(),
                4), // list of children filters
            Arguments.of(
                List.of(
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "1", ContingencyEntity.Fields.contingencyId),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l", ContingencyEntity.Fields.contingencyId),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "CURRENT", ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType)
                ),
                PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                getResultContingenciesWithNestedFilter(c -> c.getLimitViolation().getLimitType().equals(LimitViolationType.CURRENT)).stream().filter(c -> c.getContingency().getContingencyId().contains("1") && c.getContingency().getContingencyId().contains("l")).sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(),
                4) // mix of children and parent filter
        );
    }

    private static Stream<Arguments> provideEdgeCasesFilters() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 4), // empty list of filter
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "co", ContingencyEntity.Fields.status)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, ContingencyEntity.Fields.contingencyId)),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getStatus().contains("CO")).sorted(Comparator.comparing(FindContingenciesTest::getContingencyResultDTOId)).toList(), 4) // case insensitive search test
        );
    }

    private static Stream<Arguments> provideForbiddenSort() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "limitType")), new ComputationException(ComputationException.Type.INVALID_SORT_FORMAT)),
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.DESC, "side")), new ComputationException(ComputationException.Type.INVALID_SORT_FORMAT))
        );
    }

    private static Stream<Arguments> provideForbiddenFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.EQUALS, 300, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limit)), PageRequest.of(0, 30), new IllegalArgumentException("The filter type EQUALS is not supported with the data type NUMBER")),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.CONTAINS, 300, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.value)), PageRequest.of(0, 30), new IllegalArgumentException("The filter type CONTAINS is not supported with the data type NUMBER")),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.GREATER_THAN_OR_EQUAL, 300, ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.limitType)), PageRequest.of(0, 30), new IllegalArgumentException("The filter type GREATER_THAN_OR_EQUAL is not supported with the data type TEXT")),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.LESS_THAN_OR_EQUAL, 300, ContingencyEntity.Fields.contingencyId)), PageRequest.of(0, 30), new IllegalArgumentException("The filter type LESS_THAN_OR_EQUAL is not supported with the data type TEXT"))
        );
    }

    private static String getContingencyResultDTOId(ContingencyResultDTO contingencyResultDTO) {
        return contingencyResultDTO.getContingency().getContingencyId();
    }
}
