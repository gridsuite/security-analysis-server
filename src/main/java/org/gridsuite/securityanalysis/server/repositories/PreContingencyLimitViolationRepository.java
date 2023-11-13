/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

public interface PreContingencyLimitViolationRepository extends CommonLimitViolationRepository<PreContingencyLimitViolationEntity>, JpaRepository<PreContingencyLimitViolationEntity, UUID>, JpaSpecificationExecutor<PreContingencyLimitViolationEntity> {

    Page<PreContingencyLimitViolationEntity> findAll(Specification<PreContingencyLimitViolationEntity> specification, Pageable pageable);

    default Specification<PreContingencyLimitViolationEntity> getSpecification(
            UUID resultUuid,
            List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // criteria in preContingencyLimitViolationEntity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // user filters
            List<ResourceFilterDTO> parentFilters = filters.stream().filter(this::isParentFilter).toList();
            Join<Object, Object> subjectLimitViolations = (Join<Object, Object>) root.fetch("subjectLimitViolation", JoinType.INNER);
            parentFilters.forEach(filter -> addJoinFilter(criteriaBuilder, subjectLimitViolations, filter));

            if (!CriteriaUtils.currentQueryIsCountRecords(query)) {
                // criteria in preContingencyLimitViolationEntity
                List<ResourceFilterDTO> nestedFilters = filters.stream().filter(f -> !isParentFilter(f)).toList();
                nestedFilters.forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    @Override
    default void addPredicate(CriteriaBuilder criteriaBuilder,
                              Root<PreContingencyLimitViolationEntity> path,
                              List<Predicate> predicates,
                              ResourceFilterDTO filter) {

        String fieldName = switch (filter.column()) {
            case SUBJECT_ID -> "subjectLimitViolation.subjectId";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case LIMIT -> "limit";
            case VALUE -> "value";
            case ACCEPTABLE_DURATION -> "acceptableDuration";
            case SIDE -> "side";
            case LOADING -> "loading";
            default -> throw new UnsupportedOperationException("This method should be called for parent filters only");
        };
        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, fieldName);
    }

    default void addJoinFilter(CriteriaBuilder criteriaBuilder,
                               Join<?, ?> joinPath,
                               ResourceFilterDTO filter) {
        String fieldName;

        switch (filter.column()) {
            case SUBJECT_ID -> fieldName = "subjectId";
            default -> throw new UnsupportedOperationException("This method should be called for nested filters only");
        }

        CriteriaUtils.addJoinFilter(criteriaBuilder, joinPath, filter, fieldName);
    }

    default boolean isParentFilter(ResourceFilterDTO filter) {
        return ResourceFilterDTO.Column.SUBJECT_ID == filter.column();
    }

    default boolean isParentFilter(String filter) {
        return filter.equals("subjectId");
    }
}
