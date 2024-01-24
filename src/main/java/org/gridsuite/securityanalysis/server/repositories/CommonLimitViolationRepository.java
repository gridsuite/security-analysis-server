/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static java.util.function.Predicate.not;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

public interface CommonLimitViolationRepository<T> {
    /**
     * Returns specification depending on {@code filters} <br/>
     * This interface is common for both SubjectLimitViolationRepository and ContingencyRepository
     * except for <i>addPredicate</i> which needs to be implemented
     */
    default Specification<T> getParentsSpecifications(
        UUID resultUuid,
        List<ResourceFilterDTO> filters,
        boolean isSubjectLimitViolations
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();
            List<ResourceFilterDTO> childrenFilters = filters.stream().filter(not(this::isParentFilter)).toList();

            // criteria in main entity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // user filters on main entity
            filters.stream().filter(this::isParentFilter)
                .forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));

            if (!childrenFilters.isEmpty()) {
                // user filters on OneToMany collection - needed here to filter main entities that would have empty collection when filters are applied
                childrenFilters
                    .forEach(filter -> addPredicate(criteriaBuilder, root.get("contingencyLimitViolations"), predicates, filter));
            } else if (isSubjectLimitViolations) {
                // filter parents with empty children even if there isn't any filter
                predicates.add(criteriaBuilder.isNotEmpty(root.get("contingencyLimitViolations")));
            }

            // since sql joins generates duplicate results, we need to use distinct here
            query.distinct(true);

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    default Specification<T> getLimitViolationsSpecifications(
        List<UUID> contingenciesUuid,
        List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            filters.stream().filter(not(this::isParentFilter))
                .forEach(filter -> addPredicate(criteriaBuilder, root.get("contingencyLimitViolations"), predicates, filter));

            predicates.add(root.get(getIdFieldName()).in(contingenciesUuid));

            // filter on contingencyUuid
            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    default void addPredicate(CriteriaBuilder criteriaBuilder,
                              Path<?> path,
                              List<Predicate> predicates,
                              ResourceFilterDTO filter) {

        String dotSeparatedField = columnToDotSeparatedField(filter.column());
        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, dotSeparatedField);
    }

    String columnToDotSeparatedField(ResourceFilterDTO.Column column);

    boolean isParentFilter(ResourceFilterDTO filter);

    String getIdFieldName();
}
