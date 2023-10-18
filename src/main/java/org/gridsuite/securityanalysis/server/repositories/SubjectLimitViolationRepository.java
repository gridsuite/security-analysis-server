/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.FilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
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

public interface SubjectLimitViolationRepository extends JpaRepository<SubjectLimitViolationEntity, UUID>, JpaSpecificationExecutor<SubjectLimitViolationEntity> {
    Page<SubjectLimitViolationEntity> findAll(Specification<SubjectLimitViolationEntity> specification, Pageable pageable);

    static Specification<SubjectLimitViolationEntity> getSpecification(
        UUID resultUuid,
        List<FilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // criteria in SubjectLimitViolationEntity
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

    private static void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path path,
                                     List<Predicate> predicates,
                                     FilterDTO filter) {

        String fieldName = switch (filter.column()) {
            case SUBJECT_ID -> "subjectId";
            default -> throw new UnsupportedOperationException("This method should be called for parent filters only");
        };

        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, fieldName);
    }

    private static void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      FilterDTO filter) {
        String fieldName;
        String subFieldName = null;

        switch (filter.column()) {
            case CONTINGENCY_ID -> {
                fieldName = "contingency";
                subFieldName = "contingencyId";
            }
            case STATUS -> {
                fieldName = "contingency";
                subFieldName = "status";
            }
            case LIMIT_TYPE -> fieldName = "limitType";
            case LIMIT_NAME -> fieldName = "limitName";
            case SIDE -> fieldName = "side";
            default -> throw new UnsupportedOperationException("This method should be called for nested filters only");
        }

        CriteriaUtils.addJoinFilter(criteriaBuilder, joinPath, filter, fieldName, subFieldName);
    }

    private static boolean isParentFilter(FilterDTO filter) {
        return List.of(FilterDTO.FilterColumn.SUBJECT_ID).contains(filter.column());
    }
}
