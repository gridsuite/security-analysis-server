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
     * This interface is common for both SubjectLimitViolationRepository and ContingencyRepository
     * except for <i>getLimitViolationsSpecifications</i>, <i>addPredicate</i>, <i>addJoinFilter</i> and <i>isParentFilter</i> which need to be implemented
      */
    default Specification<T> getParentsSpecifications(
        UUID resultUuid,
        List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();
            List<ResourceFilterDTO> nestedFieldsFilters = filters.stream().filter(not(this::isParentFilter)).toList();

            // criteria in main entity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // filter parents by nested fields
            if (!nestedFieldsFilters.isEmpty()) {
                // if there are some filters on nested fields, we check if parents have corresponding children
                Path<?> nestedObjectPath = root.join(getNestedObjectPath());
                nestedFieldsFilters.forEach(filter -> addPredicate(criteriaBuilder, nestedObjectPath, predicates, filter));
            } else {
                // if there is not any filter, we only check if they have at least one children
                predicates.add(criteriaBuilder.isNotEmpty(root.get(getNestedObjectPath())));
            }

            // user filters
            filters.stream().filter(this::isParentFilter)
                .forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    Specification<T> getLimitViolationsSpecifications(
        List<UUID> parentsUuid,
        List<ResourceFilterDTO> filters
    );

    void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     ResourceFilterDTO filter);

    void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      ResourceFilterDTO filter);

    boolean isParentFilter(ResourceFilterDTO filter);

    String getNestedObjectPath();
}
