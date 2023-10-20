package org.gridsuite.securityanalysis.server;

import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.SecurityAnalysisResultEntity;
import org.gridsuite.securityanalysis.server.repositories.ContingencyRepository;
import org.gridsuite.securityanalysis.server.repositories.SecurityAnalysisResultRepository;
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
import org.springframework.data.jpa.domain.Specification;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;

@SpringBootTest // would be better with @DataJpaTest but does not work here
@TestInstance(TestInstance.Lifecycle.PER_CLASS) // improve tests speed as we only read DB
class ContingencyRepositoryTest {
    @Autowired
    ContingencyRepository contingencyRepository;

    @Autowired
    SecurityAnalysisResultRepository securityAnalysisResultRepository;

    SecurityAnalysisResultEntity resultEntity;

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
        "provideEachColumnFilter",
        "provideCollectionFilter",
        "provideCollectionOfFilters",
        "provideEdgeCasesFilters"
    })
    void findFilteredContingencyResultsTest(List<FilterDTO> filters, Pageable pageable, List<ContingencyResultDTO> expectedResult) {
        Specification<ContingencyEntity> specification = contingencyRepository.getSpecification(resultEntity.getId(), filters);
        Page<ContingencyEntity> contingenciesPage = contingencyRepository.findAll(specification, pageable);
        // assert contingency ids to check parent filters
        assertThat(contingenciesPage.getContent()).extracting("contingencyId").containsExactlyElementsOf(expectedResult.stream().map(c -> c.getContingency().getContingencyId()).toList());
        // assert subject limit violation ids to check nested filters
        assertThat(contingenciesPage.getContent().stream()
            .map(c -> c.getContingencyLimitViolations().stream().map(lm -> lm.getSubjectLimitViolation().getSubjectId()).toList()))
            .containsExactlyElementsOf(expectedResult.stream().map(c -> c.getSubjectLimitViolations().stream().map(SubjectLimitViolationDTO::getSubjectId).toList()).toList());
    }

    private Stream<Arguments> providePageableOnly() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30), RESULT_CONTINGENCIES),
            Arguments.of(List.of(), PageRequest.of(0, 10), RESULT_CONTINGENCIES.subList(0, 10)),
            Arguments.of(List.of(), PageRequest.of(3, 3), RESULT_CONTINGENCIES.subList(9, 12)),
            Arguments.of(List.of(), PageRequest.of(1, 10), RESULT_CONTINGENCIES.subList(10, Math.min(RESULT_CONTINGENCIES.size(), 20)))
        );
    }

    private Stream<Arguments> providePageableAndSort() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.ASC, "contingencyId")), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(this::getContingencyResultDTOId)).toList()),
            Arguments.of(List.of(), PageRequest.of(0, 30, Sort.by(Sort.Direction.DESC, "contingencyId")), RESULT_CONTINGENCIES.stream().sorted(Comparator.comparing(this::getContingencyResultDTOId).reversed()).toList())
        );
    }

    private Stream<Arguments> provideParentFilter() {
        return Stream.of(
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, "3", FilterDTO.FilterColumn.CONTINGENCY_ID)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().contains("3")).toList()),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.STARTS_WITH, "l", FilterDTO.FilterColumn.CONTINGENCY_ID)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("l")).toList()),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.STARTS_WITH, "3", FilterDTO.FilterColumn.CONTINGENCY_ID)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("3")).toList())
        );
    }

    private Stream<Arguments> provideNestedFilter() {
        return Stream.of(
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, "3", FilterDTO.FilterColumn.SUBJECT_ID)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(c -> c.getSubjectId().contains("3"))),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, "l", FilterDTO.FilterColumn.SUBJECT_ID)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(slv -> slv.getSubjectId().contains("l"))),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.STARTS_WITH, "3", FilterDTO.FilterColumn.SUBJECT_ID)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(slv -> slv.getSubjectId().startsWith("3"))),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.STARTS_WITH, "l", FilterDTO.FilterColumn.SUBJECT_ID)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(slv -> slv.getSubjectId().startsWith("l")))
        );
    }

    private Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, "CO", FilterDTO.FilterColumn.STATUS)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getComputationStatus().contains("CO")).toList()),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, "l1", FilterDTO.FilterColumn.LIMIT_NAME)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getLimitName().contains("l1"))),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, "GH", FilterDTO.FilterColumn.LIMIT_TYPE)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getLimitType().name().contains("GH"))),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, "ON", FilterDTO.FilterColumn.SIDE)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getSide() != null && lm.getLimitViolation().getSide().name().contains("ON")))
        );
    }

    private Stream<Arguments> provideCollectionFilter() {
        return Stream.of(
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, List.of("1", "3"), FilterDTO.FilterColumn.SUBJECT_ID)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(lm -> lm.getSubjectId().contains("1") || lm.getSubjectId().contains("3"))),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, List.of("GH", "CUR"), FilterDTO.FilterColumn.LIMIT_TYPE)), PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(lm -> lm.getLimitViolation().getLimitType().name().contains("GH") || lm.getLimitViolation().getLimitType().name().contains("CUR")))
        );
    }

    private Stream<Arguments> provideCollectionOfFilters() {
        return Stream.of(
            Arguments.of(
                List.of(
                    new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, List.of("1", "3"), FilterDTO.FilterColumn.SUBJECT_ID),
                    new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.CONTAINS, List.of("HIGH"), FilterDTO.FilterColumn.LIMIT_TYPE)
                ),
                PageRequest.of(0, 30),
                getResultContingenciesWithNestedFilter(lm -> (lm.getSubjectId().contains("1") || lm.getSubjectId().contains("3")) && lm.getLimitViolation().getLimitType().name().contains("HIGH")))
        );
    }

    private Stream<Arguments> provideEdgeCasesFilters() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30), RESULT_CONTINGENCIES),
            Arguments.of(List.of(new FilterDTO(FilterDTO.DataType.TEXT, FilterDTO.Type.STARTS_WITH, List.of(), FilterDTO.FilterColumn.SUBJECT_ID)), PageRequest.of(0, 30), RESULT_CONTINGENCIES)
        );
    }

    private String getContingencyResultDTOId(ContingencyResultDTO contingencyResultDTO) {
        return contingencyResultDTO.getContingency().getContingencyId();
    }
}
