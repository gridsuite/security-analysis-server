package org.gridsuite.securityanalysis.server.util;

import com.powsybl.iidm.network.ThreeSides;
import org.gridsuite.computation.dto.ResourceFilterDTO;
import org.gridsuite.computation.utils.SpecificationUtils;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ContingencyLimitViolationWorstSideUtilsTest {
    private static final String SIDE_COLUMN = SubjectLimitViolationEntity.Fields.contingencyLimitViolations
        + SpecificationUtils.FIELD_SEPARATOR
        + AbstractLimitViolationEntity.Fields.side;
    private static final String IS_WORST_SIDE_COLUMN = SubjectLimitViolationEntity.Fields.contingencyLimitViolations
        + SpecificationUtils.FIELD_SEPARATOR
        + ContingencyLimitViolationEntity.Fields.isWorstSide;

    @Test
    void shouldComputeWorstSideBySubjectId() {
        ContingencyLimitViolationEntity subject1Worst = createContingencyLimitViolation("subject1", 60, 120, 101., ThreeSides.TWO);
        ContingencyLimitViolationEntity subject1Other = createContingencyLimitViolation("subject1", 120, 60, 130., ThreeSides.ONE);
        ContingencyLimitViolationEntity subject2Worst = createContingencyLimitViolation("subject2", 30, 60, 101., ThreeSides.TWO);
        ContingencyLimitViolationEntity subject2Other = createContingencyLimitViolation("subject2", 60, 30, 130., ThreeSides.ONE);

        ContingencyLimitViolationWorstSideUtils.computeWorstSideBySubjectId(List.of(
            subject1Other,
            subject2Other,
            subject1Worst,
            subject2Worst
        ));

        assertThat(subject1Worst.isWorstSide()).isTrue();
        assertThat(subject1Other.isWorstSide()).isFalse();
        assertThat(subject2Worst.isWorstSide()).isTrue();
        assertThat(subject2Other.isWorstSide()).isFalse();
    }

    @Test
    void shouldUseUpcomingAcceptableDurationWhenAcceptableDurationIsEqual() {
        ContingencyLimitViolationEntity worst = createContingencyLimitViolation("subject", 60, 60, 101., ThreeSides.TWO);
        ContingencyLimitViolationEntity other = createContingencyLimitViolation("subject", 60, 120, 130., ThreeSides.ONE);

        ContingencyLimitViolationWorstSideUtils.computeWorstSideBySubjectId(List.of(other, worst));

        assertThat(worst.isWorstSide()).isTrue();
        assertThat(other.isWorstSide()).isFalse();
    }

    @Test
    void shouldUseLoadingWhenDurationsAreEqual() {
        ContingencyLimitViolationEntity worst = createContingencyLimitViolation("subject", 60, 120, 130., ThreeSides.TWO);
        ContingencyLimitViolationEntity other = createContingencyLimitViolation("subject", 60, 120, 101., ThreeSides.ONE);

        ContingencyLimitViolationWorstSideUtils.computeWorstSideBySubjectId(List.of(other, worst));

        assertThat(worst.isWorstSide()).isTrue();
        assertThat(other.isWorstSide()).isFalse();
    }

    @Test
    void shouldUseSideNumberWhenDurationsAndLoadingAreEqual() {
        ContingencyLimitViolationEntity worst = createContingencyLimitViolation("subject", 60, 120, 101., ThreeSides.ONE);
        ContingencyLimitViolationEntity other = createContingencyLimitViolation("subject", 60, 120, 101., ThreeSides.TWO);

        ContingencyLimitViolationWorstSideUtils.computeWorstSideBySubjectId(List.of(other, worst));

        assertThat(worst.isWorstSide()).isTrue();
        assertThat(other.isWorstSide()).isFalse();
    }

    @Test
    void shouldTreatNullDurationsAndLoadingAsLeastCritical() {
        ContingencyLimitViolationEntity worst = createContingencyLimitViolation("subject", 60, 120, 101., ThreeSides.ONE);
        ContingencyLimitViolationEntity other = createContingencyLimitViolation("subject", null, null, null, ThreeSides.TWO);

        ContingencyLimitViolationWorstSideUtils.computeWorstSideBySubjectId(List.of(other, worst));

        assertThat(worst.isWorstSide()).isTrue();
        assertThat(other.isWorstSide()).isFalse();
    }

    @Test
    void shouldNormalizeWorstSideFilter() {
        ResourceFilterDTO filterToNormalize = new ResourceFilterDTO(
            ResourceFilterDTO.DataType.TEXT,
            ResourceFilterDTO.Type.EQUALS,
            List.of("ONE", "worst"),
            SIDE_COLUMN
        );
        ResourceFilterDTO otherFilter = new ResourceFilterDTO(
            ResourceFilterDTO.DataType.TEXT,
            ResourceFilterDTO.Type.CONTAINS,
            "subject",
            SubjectLimitViolationEntity.Fields.subjectId
        );

        List<ResourceFilterDTO> normalizedFilters = ContingencyLimitViolationWorstSideUtils.normalizeWorstSideFilter(
            List.of(filterToNormalize, otherFilter)
        );

        assertThat(normalizedFilters).containsExactly(
            new ResourceFilterDTO(
                ResourceFilterDTO.DataType.BOOLEAN,
                ResourceFilterDTO.Type.EQUALS,
                true,
                IS_WORST_SIDE_COLUMN
            ),
            otherFilter
        );
    }

    // below tests are currently the same, but they cover potential changes in contingencyLimitViolations on any of the entities structure that could break "normalizeWorstSideFilter"
    @Test
    void shouldNormalizeContingencyWorstSideFilterWithOtherColumn() {
        shouldNormalizeWorstSideFilterWithOtherColumn(
            ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side,
            ContingencyEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.isWorstSide
        );
    }

    @Test
    void shouldNormalizeSubjectLimitViolationsWorstSideFilterWithOtherColumn() {
        shouldNormalizeWorstSideFilterWithOtherColumn(
            SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side,
            SubjectLimitViolationEntity.Fields.contingencyLimitViolations + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.isWorstSide
        );
    }

    private void shouldNormalizeWorstSideFilterWithOtherColumn(String sideColumn, String isWorstSideColumn) {
        ResourceFilterDTO filterToNormalize = new ResourceFilterDTO(
            ResourceFilterDTO.DataType.TEXT,
            ResourceFilterDTO.Type.EQUALS,
            List.of("WoRsT"),
            sideColumn
        );

        List<ResourceFilterDTO> normalizedFilters = ContingencyLimitViolationWorstSideUtils.normalizeWorstSideFilter(
            List.of(filterToNormalize)
        );

        assertThat(normalizedFilters).containsExactly(
            new ResourceFilterDTO(
                ResourceFilterDTO.DataType.BOOLEAN,
                ResourceFilterDTO.Type.EQUALS,
                true,
                isWorstSideColumn
            )
        );
    }

    @Test
    void shouldNotNormalizeSideFilterWithoutWorstValue() {
        ResourceFilterDTO sideFilter = new ResourceFilterDTO(
            ResourceFilterDTO.DataType.TEXT,
            ResourceFilterDTO.Type.EQUALS,
            List.of("ONE", "TWO"),
            SIDE_COLUMN
        );

        List<ResourceFilterDTO> normalizedFilters = ContingencyLimitViolationWorstSideUtils.normalizeWorstSideFilter(List.of(
            sideFilter
        ));

        assertThat(normalizedFilters).containsExactly(sideFilter);
    }

    private static ContingencyLimitViolationEntity createContingencyLimitViolation(String subjectId,
                                                                                   Integer acceptableDuration,
                                                                                   Integer upcomingAcceptableDuration,
                                                                                   Double loading,
                                                                                   ThreeSides side) {
        return ContingencyLimitViolationEntity.builder()
            .subjectLimitViolation(new SubjectLimitViolationEntity(subjectId, subjectId))
            .acceptableDuration(acceptableDuration)
            .upcomingAcceptableDuration(upcomingAcceptableDuration)
            .loading(loading)
            .side(side)
            .build();
    }
}
