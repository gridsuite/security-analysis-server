/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
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
            filters.stream().filter(not(this::isParentFilter))
                .forEach(filter -> addPredicate(criteriaBuilder, getFilterPath(root), predicates, filter));

            query.distinct(true);

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    default Specification<ContingencyEntity> getLimitViolationsSpecifications(
        List<UUID> contingenciesUuid,
        List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            // join fetch contingencyLimitViolation table
            Join<Object, Object> contingencyLimitViolation = (Join<Object, Object>) root.fetch("contingencyLimitViolations", JoinType.LEFT);

            // criteria in contingencyLimitViolationEntity
            // user filters
            filters.stream().filter(not(this::isParentFilter))
                .forEach(filter -> addJoinFilter(criteriaBuilder, contingencyLimitViolation, filter));

            // filter on contingencyUuid
            return root.get("uuid").in(contingenciesUuid);
        };
    }

    void addPredicate(CriteriaBuilder criteriaBuilder,
                      Path<?> path,
                      List<Predicate> predicates,
                      ResourceFilterDTO filter);

    void addJoinFilter(CriteriaBuilder criteriaBuilder,
                       Join<?, ?> joinPath,
                       ResourceFilterDTO filter);

    boolean isParentFilter(ResourceFilterDTO filter);

    Path<?> getFilterPath(Root<?> root);



    interface ContingencyUuid {
        UUID getUuid();
    }
}
