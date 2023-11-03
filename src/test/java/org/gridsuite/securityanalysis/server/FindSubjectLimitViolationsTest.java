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

import static org.assertj.core.api.Assertions.assertThat;
import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;

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
        "provideParentFilter",
        "provideNestedFilter",
        "provideEachColumnFilter"
    })
    void findFilteredSubjectLimitViolationResultsTest(List<ResourceFilterDTO> filters, Pageable pageable, List<SubjectLimitViolationResultDTO> expectedResult) {
        Page<SubjectLimitViolationEntity> subjectLimitViolationPage = securityAnalysisResultService.findSubjectLimitViolationsPage(resultEntity.getId(), filters, pageable);
        // assert subject ids to check parent filters
        assertThat(subjectLimitViolationPage.getContent()).extracting("subjectId").containsExactlyElementsOf(expectedResult.stream().map(c -> c.getSubjectId()).toList());
        // assert limit violation contingency ids to check nested filters
        assertThat(subjectLimitViolationPage.getContent().stream()
            .map(c -> c.getContingencyLimitViolations().stream().map(lm -> lm.getContingency().getContingencyId()).toList()))
            .containsExactlyElementsOf(expectedResult.stream().map(c -> c.getContingencies().stream().map(this::getContingencyLimitViolationDTOContingencyId).toList()).toList());
    }

    private Stream<Arguments> providePageableOnly() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30), RESULT_CONSTRAINTS),
            Arguments.of(List.of(), PageRequest.of(0, 2), RESULT_CONSTRAINTS.subList(0, 2)),
            Arguments.of(List.of(), PageRequest.of(1, 2), RESULT_CONSTRAINTS.subList(2, Math.min(RESULT_CONSTRAINTS.size(), 4)))
        );
    }

    private Stream<Arguments> providePageableAndSort() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId)).toList()),
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.DESC, "subjectId")), RESULT_CONSTRAINTS.stream().sorted(Comparator.comparing(SubjectLimitViolationResultDTO::getSubjectId).reversed()).toList())
        );
    }

    private Stream<Arguments> provideParentFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", ResourceFilterDTO.Column.SUBJECT_ID)), PageRequest.of(0, 30),
                RESULT_CONSTRAINTS.stream().filter(c -> c.getSubjectId().contains("3")).toList()),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", ResourceFilterDTO.Column.SUBJECT_ID)), PageRequest.of(0, 30),
                RESULT_CONSTRAINTS.stream().filter(c -> c.getSubjectId().startsWith("l")).toList()),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", ResourceFilterDTO.Column.SUBJECT_ID)), PageRequest.of(0, 30),
                RESULT_CONSTRAINTS.stream().filter(c -> c.getSubjectId().startsWith("3")).toList())
        );
    }

    private Stream<Arguments> provideNestedFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getContingency().getContingencyId().contains("3"))),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getContingency().getContingencyId().contains("l"))),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getContingency().getContingencyId().startsWith("3"))),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getContingency().getContingencyId().startsWith("l")))
        );
    }

    private Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "CO", ResourceFilterDTO.Column.STATUS)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getContingency().getStatus().contains("CO"))),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "l1", ResourceFilterDTO.Column.LIMIT_NAME)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getLimitViolation().getLimitName().contains("l1"))),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "GH", ResourceFilterDTO.Column.LIMIT_TYPE)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getLimitViolation().getLimitType().name().contains("GH"))),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "ON", ResourceFilterDTO.Column.SIDE)), PageRequest.of(0, 30),
                getResultConstraintsWithNestedFilter(lm -> lm.getLimitViolation().getSide() != null && lm.getLimitViolation().getSide().name().contains("ON")))
        );
    }

    private String getContingencyLimitViolationDTOContingencyId(ContingencyLimitViolationDTO contingencyLimitViolationDTO) {
        return contingencyLimitViolationDTO.getContingency().getContingencyId();
    }
}
