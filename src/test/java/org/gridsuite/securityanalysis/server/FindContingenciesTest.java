package org.gridsuite.securityanalysis.server;

import org.gridsuite.securityanalysis.server.dto.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
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
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.gridsuite.securityanalysis.server.SecurityAnalysisProviderMock.*;

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
        "providePageableOnly",
        "providePageableAndSort",
        "provideParentFilter",
        "provideEachColumnFilter",
        "provideCollectionFilter",
        "provideCollectionOfFilters",
        "provideEdgeCasesFilters"
    })
    void findFilteredContingencyResultsTest(List<ResourceFilterDTO> filters, Pageable pageable, List<ContingencyResultDTO> expectedResult) {
        Page<ContingencyEntity> contingenciesPage = securityAnalysisResultService.findContingenciesPage(resultEntity.getId(), filters, pageable);
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
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "3", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().contains("3")).toList()),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "l", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("l")).toList()),
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, "3", ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().startsWith("3")).toList())
        );
    }

    private Stream<Arguments> provideEachColumnFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "CO", ResourceFilterDTO.Column.STATUS)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getStatus().contains("CO")).toList())
        );
    }

    private Stream<Arguments> provideCollectionFilter() {
        return Stream.of(
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, List.of("l", "3"), ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getContingencyId().contains("l") || c.getContingency().getContingencyId().contains("3")).toList())
        );
    }

    private Stream<Arguments> provideCollectionOfFilters() {
        return Stream.of(
            Arguments.of(
                List.of(
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, List.of("1", "3"), ResourceFilterDTO.Column.CONTINGENCY_ID),
                    new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.EQUALS, List.of("CONVERGED"), ResourceFilterDTO.Column.STATUS)
                ),
                PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> (c.getContingency().getContingencyId().contains("1") || c.getContingency().getContingencyId().contains("3")) && c.getContingency().getStatus().equals("CONVERGED")).toList())
        );
    }

    private Stream<Arguments> provideEdgeCasesFilters() {
        return Stream.of(
            Arguments.of(List.of(), PageRequest.of(0, 30), RESULT_CONTINGENCIES), // empty list of filter
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.STARTS_WITH, List.of(), ResourceFilterDTO.Column.CONTINGENCY_ID)), PageRequest.of(0, 30), RESULT_CONTINGENCIES), // empty list of values in filter
            Arguments.of(List.of(new ResourceFilterDTO(ResourceFilterDTO.DataType.TEXT, ResourceFilterDTO.Type.CONTAINS, "co", ResourceFilterDTO.Column.STATUS)), PageRequest.of(0, 30),
                RESULT_CONTINGENCIES.stream().filter(c -> c.getContingency().getStatus().contains("CO")).toList()) // case insensitive search test
        );
    }

    private String getContingencyResultDTOId(ContingencyResultDTO contingencyResultDTO) {
        return contingencyResultDTO.getContingency().getContingencyId();
    }
}
