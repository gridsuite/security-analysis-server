package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

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

            // criteria in main entity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

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
                                     Root<T> path,
                                     List<Predicate> predicates,
                                     ResourceFilterDTO filter);

    void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      ResourceFilterDTO filter);

    boolean isParentFilter(ResourceFilterDTO filter);
}
