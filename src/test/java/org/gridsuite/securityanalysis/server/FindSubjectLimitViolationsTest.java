/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import org.gridsuite.securityanalysis.server.dto.*;
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

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
@SpringBootTest // would be better with @DataJpaTest but does not work here
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // improve tests speed as we only read DB
class FindSubjectLimitViolationsTest {
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
        "providePageableOnly",
        "providePageableAndSort",
        "provideParentFilter"
    })
    void findFilteredSubjectLimitViolationResultsTest(List<ResourceFilterDTO> filters, Pageable pageable, List<SubjectLimitViolationResultDTO> expectedResult, Integer selectCount) {
        reset();
        Page<SubjectLimitViolationEntity> subjectLimitViolationPage = securityAnalysisResultService.findSubjectLimitViolationsPage(resultEntity.getId(), filters, pageable);
        // select count check to prevent potential n+1 problems
        // 1 -> parent ; empty parents, no count or children request
        // 2 -> parent + children ; no count (number of element < page size)
        // 3 -> parent + count + children
        assertSelectCount(selectCount);

        // assert subject ids to check parent filters
        assertThat(subjectLimitViolationPage.getContent()).extracting("subjectId").containsExactlyElementsOf(expectedResult.stream().map(c -> c.getSubjectId()).toList());
        // assert limit violation contingency ids to check nested filters
        assertThat(subjectLimitViolationPage.getContent().stream()
            .map(c -> c.getContingencyLimitViolations().stream().map(lm -> lm.getContingency().getContingencyId()).toList()))
            .containsExactlyElementsOf(expectedResult.stream().map(c -> c.getContingencies().stream().map(this::getContingencyLimitViolationDTOContingencyId).toList()).toList());
    }

    private Stream<Arguments> providePageableOnly() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30), RESULT_CONSTRAINTS, 2),
            Arguments.of(List.of(), PageRequest.of(0, 2), RESULT_CONSTRAINTS.subList(0, 2), 3),
            Arguments.of(List.of(), PageRequest.of(1, 2), RESULT_CONSTRAINTS.subList(2, Math.min(RESULT_CONSTRAINTS.size(), 4)), 2)
        );
    }

    private Stream<Arguments> providePageableAndSort() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList(), 2),
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.DESC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId).reversed()).toList(), 2)
        );
    }

    private Stream<Arguments> provideParentFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", ResourceFilterDTO.Column.SUBJECT_ID)), PageRequest.of(0, 30),
                RESULT_CONSTRAINTS.stream().filter(c -> c.getSubjectId().contains("3")).toList(), 2),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", ResourceFilterDTO.Column.SUBJECT_ID)), PageRequest.of(0, 30),
                RESULT_CONSTRAINTS.stream().filter(c -> c.getSubjectId().startsWith("l")).toList(), 2),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", ResourceFilterDTO.Column.SUBJECT_ID)), PageRequest.of(0, 30),
                RESULT_CONSTRAINTS.stream().filter(c -> c.getSubjectId().startsWith("3")).toList(), 1)
        );
    }

    private String getContingencyLimitViolationDTOContingencyId(ContingencyLimitViolationDTO contingencyLimitViolationDTO) {
        return contingencyLimitViolationDTO.getContingency().getContingencyId();
    }
}
