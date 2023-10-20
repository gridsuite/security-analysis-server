package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.FilterDTO;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

public interface CommonLimitViolationRepository<T> {
    default Specification<T> getSpecification(
        UUID resultUuid,
        List<FilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // criteria in contingencyEntity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // user filters
            List<FilterDTO> parentFilters = filters.stream().filter(f -> isParentFilter(f)).toList();
            parentFilters.forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));

            // pageable makes a count request which should only count contingency results, not joined rows
            if (!CriteriaUtils.currentQueryIsCountRecords(query)) {
                // join fetch contingencyLimitViolation table
                Join<Object, Object> contingencyLimitViolation = (Join<Object, Object>) root.fetch("contingencyLimitViolations", JoinType.LEFT);

                // criteria in contingencyLimitViolationEntity
                List<FilterDTO> nestedFilters = filters.stream().filter(f -> !isParentFilter(f)).toList();
                nestedFilters.forEach(filter -> addJoinFilter(criteriaBuilder, contingencyLimitViolation, filter));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Root<T> path,
                                     List<Predicate> predicates,
                                     FilterDTO filter);

    void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      FilterDTO filter);

    boolean isParentFilter(FilterDTO filter);
}
