/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
import org.gridsuite.securityanalysis.server.service.SecurityAnalysisResultService;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
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

import static com.vladmihalcea.sql.SQLStatementCountValidator.assertSelectCount;
import static com.vladmihalcea.sql.SQLStatementCountValidator.reset;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

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
    SecurityAnalysisResultRepository securityAnalysisResultRepository;

    SecurityAnalysisResultEntity resultEntity;

    @Autowired
    SecurityAnalysisResultService securityAnalysisResultService;

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
        "provideEachColumnFilter",
        "provideCollectionFilter",
        "provideCollectionOfFilters",
        "provideEdgeCasesFilters"
    })
    void findFilteredContingencyResultsTest(List<ResourceFilterDTO> filters, Pageable pageable, List<ContingencyResultDTO> expectedResult, Integer expectedSelectCount) {
        reset();
        Page<ContingencyEntity> contingenciesPage = securityAnalysisResultService.findContingenciesPage(resultEntity.getId(), filters, pageable);

        // assert contingency ids to check parent filters
        assertThat(contingenciesPage.getContent()).extracting("contingencyId").containsExactlyElementsOf(expectedResult.stream().map(c -> c.getContingency().getContingencyId()).toList());
        // assert subject limit violation ids to check nested filters
        assertThat(contingenciesPage.getContent().stream()
            .map(c -> ContingencyResultDTO.toDto(c)) // call toDTO method to check if it provokes any more requests
            .map(c -> c.getSubjectLimitViolations().stream().map(lm -> lm.getSubjectId()).toList()))
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
        Exception exception = assertThrows(expectedException.getClass(), () ->  securityAnalysisResultService.findContingenciesPage(resultEntity.getId(), filters, pageable));
        assertEquals(expectedException.getMessage(), exception.getMessage());
    }

    private Stream<Arguments> providePageableAndSortOnly() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 5, Sort.by(Sort.Direction.ASC, "contingencyId")), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList().subList(0, 5), 5),
            Arguments.of(List.of(), PageRequest.of(0, 5, Sort.by(Sort.Direction.DESC, "contingencyId")), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(this::getContingencyResultDTOId).reversed()).toList().subList(0, 5), 5)
        );
    }

    private Stream<Arguments> provideParentFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().contains("3")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("l")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("3")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 1)
        );
    }

    private Stream<Arguments> provideChildFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l6", ResourceFilterDTO.Column.SUBJECT_ID)), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, "contingencyId")),
                getResultContingenciesWithNestedFilter(lm -> lm.getSubjectId().equals("l6"))
                    .stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList()
                    .subList(0, 2), 5), // find 1st page of size 2 of contingencies, filtered by SubjectId
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "CURRENT", ResourceFilterDTO.Column.LIMIT_TYPE)), PageRequest.of(0, 2, Sort.by(Sort.Direction.ASC, "contingencyId")),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getLimitType().equals(LimitViolationType.CURRENT))
                    .stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList()
                    .subList(0, 2), 5)
        );
    }

    private Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "CO", ResourceFilterDTO.Column.STATUS)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getStatus().contains("CO")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "ONE", ResourceFilterDTO.Column.SIDE)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getSide() != null && lm.getLimitViolation().getSide().equals(Branch.Side.ONE)).stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "l6_name", ResourceFilterDTO.Column.LIMIT_NAME)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getLimitName().equals("l6_name")).stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4)
        );
    }

    private Stream<Arguments> provideCollectionFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, List.of("l", "3"), ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().contains("l") || c.getContingency().getContingencyId().contains("3")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4)
        );
    }

    private Stream<Arguments> provideCollectionOfFilters() {
        return Stream.of(
            Arguments.of(
                List.of(
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, List.of("1", "3"), ResourceFilterDTO.Column.CONTINGENCY_ID),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, List.of("CONVERGED"), ResourceFilterDTO.Column.STATUS)
                ),
                PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                RESULT_CONTINGENCIES.stream().filter(c -> (c.getContingency().getContingencyId().contains("1") || c.getContingency().getContingencyId().contains("3")) && c.getContingency().getStatus().equals("CONVERGED")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(),
                4), // list of parent filters
            Arguments.of(
                List.of(
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, List.of("l6"), ResourceFilterDTO.Column.SUBJECT_ID),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, List.of("CURRENT"), ResourceFilterDTO.Column.LIMIT_TYPE)
                ),
                PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                getResultContingenciesWithNestedFilter(c -> c.getSubjectId().equals("l6") && c.getLimitViolation().getLimitType().equals(LimitViolationType.CURRENT)).stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(),
                4), // list of children filters
            Arguments.of(
                List.of(
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, List.of("1", "3"), ResourceFilterDTO.Column.CONTINGENCY_ID),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, List.of("CURRENT"), ResourceFilterDTO.Column.LIMIT_TYPE)
                ),
                PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                getResultContingenciesWithNestedFilter(c -> c.getLimitViolation().getLimitType().equals(LimitViolationType.CURRENT)).stream().filter(c -> c.getContingency().getContingencyId().contains("1") || c.getContingency().getContingencyId().contains("3")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(),
                4) // mix of children and parent filter
        );
    }

    private Stream<Arguments> provideEdgeCasesFilters() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4), // empty list of filter
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, List.of(), ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4), // empty list of values in filter
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "co", ResourceFilterDTO.Column.STATUS)), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getStatus().contains("CO")).sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList(), 4) // case insensitive search test
        );
    }

    private Stream<Arguments> provideForbiddenSort() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "limitType")), new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_SORT_FORMAT)),
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.DESC, "side")), new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_SORT_FORMAT))
        );
    }

    private Stream<Arguments> provideForbiddenFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, List.of(), ResourceFilterDTO.Column.LIMIT)), PageRequest.of(0, 30), new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_FILTER)),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, List.of(), ResourceFilterDTO.Column.VALUE)), PageRequest.of(0, 30), new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_FILTER))
        );
    }

    private String getContingencyResultDTOId(ContingencyResultDTO contingencyResultDTO) {
        return contingencyResultDTO.getContingency().getContingencyId();
    }
}
