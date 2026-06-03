package org.gridsuite.securityanalysis.server.util;

import org.gridsuite.computation.dto.ResourceFilterDTO;
import org.gridsuite.computation.utils.SpecificationUtils;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;

import java.util.*;
import java.util.stream.Collectors;

public final class ContingencyLimitViolationWorstSideUtils {
    private static final String WORST_SIDE_VALUE = "worst";
    private static final String SIDE_FIELD = "contingencyLimitViolations" + SpecificationUtils.FIELD_SEPARATOR + AbstractLimitViolationEntity.Fields.side;
    private static final String IS_WORST_SIDE_FIELD = "contingencyLimitViolations" + SpecificationUtils.FIELD_SEPARATOR + ContingencyLimitViolationEntity.Fields.isWorstSide;

    private ContingencyLimitViolationWorstSideUtils() {
        throw new UnsupportedOperationException("ContingencyLimitViolationWorstSideUtils Utility class and cannot be instantiated");
    }

    private static final Comparator<ContingencyLimitViolationEntity> WORSE_SIDE_COMPARATOR = Comparator.comparing(
            ContingencyLimitViolationEntity::getAcceptableDuration,
            Comparator.nullsLast(Comparator.naturalOrder()))
        .thenComparing(
            ContingencyLimitViolationEntity::getUpcomingAcceptableDuration,
            Comparator.nullsLast(Comparator.naturalOrder()))
        .thenComparing(
            ContingencyLimitViolationEntity::getLoading,
            Comparator.nullsLast(Comparator.reverseOrder()))
        .thenComparing(
            clv -> clv.getSide() != null ? clv.getSide().getNum() : null,
            Comparator.nullsLast(Comparator.naturalOrder()));

    /**
     * Computes the worst side for each SubjectLimitViolationEntity.subjectId + ContingencyEntity.contingencyId pair
     * IMPORTANT : All contingencyLimitViolations must be from the same contingency
     */
    public static void computeWorstSideBySubjectId(List<ContingencyLimitViolationEntity> contingencyLimitViolations) {
        Map<String, List<ContingencyLimitViolationEntity>> violationsBySubjectAndContingency = contingencyLimitViolations.stream()
            .collect(Collectors.groupingBy(clv -> clv.getSubjectLimitViolation().getSubjectId()));

        violationsBySubjectAndContingency.values().forEach(violations -> {
            ContingencyLimitViolationEntity worstViolation = Collections.min(violations, WORSE_SIDE_COMPARATOR);

            violations.forEach(violation -> violation.setWorstSide(violation == worstViolation));
        });
    }

    public static List<ResourceFilterDTO> normalizeWorstSideFilter(List<ResourceFilterDTO> resourceFilters) {
        return resourceFilters.stream().map(resourceFilterDTO -> {
            if (isWorstSideFilter(resourceFilterDTO)) {
                return new ResourceFilterDTO(
                    ResourceFilterDTO.DataType.BOOLEAN,
                    ResourceFilterDTO.Type.EQUALS,
                    true,
                    IS_WORST_SIDE_FIELD
                );
            }
            return resourceFilterDTO;
        }).toList();
    }

    private static boolean isWorstSideFilter(ResourceFilterDTO resourceFilter) {
        return resourceFilter.column().equals(SIDE_FIELD)
            && resourceFilter.value() instanceof Collection<?> valuesAsCollection
            && valuesAsCollection.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .anyMatch(WORST_SIDE_VALUE::equalsIgnoreCase);
    }
}
