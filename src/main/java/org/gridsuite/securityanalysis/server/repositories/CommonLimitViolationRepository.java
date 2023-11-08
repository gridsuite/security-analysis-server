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
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

public interface CommonLimitViolationRepository<T> {
    /**
     * Returns specification depending on {filters}
     * This interface is common for both SubjectLimitViolationRepository and ContingencyRepository
     * except for <i>addPredicate</i> which need to be implemented
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
            filters.stream()
                    .forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    void addPredicate(CriteriaBuilder criteriaBuilder,
                      Root<T> path,
                      List<Predicate> predicates,
                      ResourceFilterDTO filter);
}
