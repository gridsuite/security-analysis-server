/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.ThreeSides;
import org.gridsuite.securityanalysis.server.dto.PreContingencyLimitViolationResultDTO;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;
import org.gridsuite.securityanalysis.server.dto.SubjectLimitViolationResultDTO;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
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
 * @author Anis Touri <anis.touri at rte-france.com>
 */
@SpringBootTest // would be better with @DataJpaTest but does not work here
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // improve tests speed as we only read DB
class FindPreContingencyLimitViolationTest {
    @Autowired
    SecurityAnalysisResultRepository securityAnalysisResultRepository;

    SecurityAnalysisResultEntity resultEntity;

    @Autowired
    SecurityAnalysisResultService securityAnalysisResultService;

    @BeforeAll
    void setUp() {
        resultEntity = SecurityAnalysisResultEntity.toEntity(UUID.randomUUID(), PRECONTINGENCY_RESULT, SecurityAnalysisStatus.CONVERGED);
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
        "provideEachColumnFilter"
    })
    void findFilteredPrecontingencyLimitViolationResultsTest(List<ResourceFilterDTO> filters, Sort sort, List<PreContingencyLimitViolationResultDTO> expectedResult, Integer expectedSelectCount) {
        reset();
        List<PreContingencyLimitViolationResultDTO> preContingencyLimitViolation = securityAnalysisResultService.findNResult(resultEntity.getId(), filters, sort);

        // assert subject ids to check parent filters
        assertThat(preContingencyLimitViolation).extracting("subjectId").containsExactlyElementsOf(expectedResult.stream().map(c -> c.getSubjectId()).toList());
        assertSelectCount(expectedSelectCount);
    }

    private Stream<Arguments> provideSortOnly() {
        return Stream.of(
                Arguments.of(List.of(), Sort.by(Sort.Direction.ASC, "subjectId"), RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).toList(), 2),
                Arguments.of(List.of(), Sort.by(Sort.Direction.DESC, "subjectId"), RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId).reversed()).toList(), 2)
        );
    }

    private Stream<Arguments> provideParentFilter() {
        return Stream.of(
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", "subjectLimitViolation." + ResourceFilterDTO.Column.SUBJECT_ID.getColumnName())), Sort.by(Sort.Direction.ASC, "subjectId"),
                        RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().contains("3")).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", "subjectLimitViolation." + ResourceFilterDTO.Column.SUBJECT_ID.getColumnName())), Sort.by(Sort.Direction.ASC, "subjectId"),
                        RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().startsWith("l")).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", "subjectLimitViolation." + ResourceFilterDTO.Column.SUBJECT_ID.getColumnName())), Sort.by(Sort.Direction.ASC, "subjectId"),
                        RESULT_PRECONTINGENCY.stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).filter(c -> c.getSubjectId().startsWith("3")).toList(), 2)
        );
    }

    private Stream<Arguments> provideChildFilter() {
        return Stream.of(
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l6", "subjectLimitViolation." + ResourceFilterDTO.Column.SUBJECT_ID.getColumnName())), Sort.by(Sort.Direction.ASC, "subjectId"),
                        getResultPreContingencyWithNestedFilter(p -> p.getSubjectId().contains("l6"))
                                .stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.NUMBER, ResourceFilterDTO.Type.LESS_THAN_OR_EQUAL, "390", ResourceFilterDTO.Column.LIMIT.getColumnName())), Sort.by(Sort.Direction.ASC, "limit"),
                        getResultPreContingencyWithNestedFilter(p -> p.getLimitViolation().getLimit() <= 390)
                                .stream().sorted(Comparator.comparing(x -> x.getLimitViolation().getLimit())).toList(), 2)
        );
    }

    private Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "ONE", ResourceFilterDTO.Column.SIDE.getColumnName())), Sort.by(Sort.Direction.ASC, "subjectId"),
                        getResultPreContingencyWithNestedFilter(c -> c.getLimitViolation().getSide() != null && c.getLimitViolation().getSide().equals(ThreeSides.ONE)).stream().sorted(Comparator.comparing(PreContingencyLimitViolationResultDTO::getSubjectId)).toList(), 2),
                Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, "l5_name", ResourceFilterDTO.Column.LIMIT_NAME.getColumnName())), Sort.by(Sort.Direction.ASC, "subjectId"),
                        getResultConstraintsWithNestedFilter(c -> c.getLimitViolation().getLimitName().equals("l5_name")).stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList(), 2)
        );
    }
}
