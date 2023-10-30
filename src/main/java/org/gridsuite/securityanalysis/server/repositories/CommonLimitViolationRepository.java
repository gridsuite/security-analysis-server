package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static java.util.function.Predicate.not;

public interface CommonLimitViolationRepository<T> {
    /**
     * Returns specification depending on {filters}
     * This method is common for both SubjectLimitViolationRepository and ContingencyRepository
     * except for <i>addPredicate</i>, <i>addJoinFilter</i> and <i>isParentFilter</i> which need to be implemented
      */
    default Specification<T> getSpecification(
        UUID resultUuid,
        List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // criteria in contingencyEntity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // user filters
            filters.stream().filter(this::isParentFilter)
                .forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));

            // pageable makes a count request which should only count contingency results, not joined rows
            if (!CriteriaUtils.currentQueryIsCountRecords(query)) {
                // join fetch contingencyLimitViolation table
                Join<Object, Object> contingencyLimitViolation = (Join<Object, Object>) root.fetch("contingencyLimitViolations", JoinType.LEFT);

                // criteria in contingencyLimitViolationEntity
                filters.stream().filter(not(this::isParentFilter))
                    .forEach(filter -> addJoinFilter(criteriaBuilder, contingencyLimitViolation, filter));
            }

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Root<T> path,
                                     List<Predicate> predicates,
                                     ResourceFilterDTO filter);

    void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      ResourceFilterDTO filter);

    boolean isParentFilter(ResourceFilterDTO filter);
}
