/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.FilterDTO;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

public interface PreContingencyLimitViolationRepository extends  CommonLimitViolationRepository<PreContingencyLimitViolationEntity>, JpaRepository<PreContingencyLimitViolationEntity, UUID>, JpaSpecificationExecutor<PreContingencyLimitViolationEntity>{

    //List<PreContingencyLimitViolationEntity> findByResultId(UUID resultUuid);
    Page<PreContingencyLimitViolationEntity> findAll(Specification<PreContingencyLimitViolationEntity> specification, Pageable pageable);

    default Specification<PreContingencyLimitViolationEntity> getSpecification(
            UUID resultUuid,
            List<FilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // criteria in contingencyEntity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // user filters
            //List<FilterDTO> parentFilters = filters.stream().filter(this::isParentFilter).toList();
            filters.forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));

            // pageable makes a count request which should only count contingency results, not joined rows
            if (!CriteriaUtils.currentQueryIsCountRecords(query)) {
                // join fetch contingencyLimitViolation table
                Join<Object, Object> contingencyLimitViolation = null;

                // criteria in contingencyLimitViolationEntity
                //List<FilterDTO> nestedFilters = filters.stream().filter(f -> !isParentFilter(f)).toList();
                filters.forEach(filter -> addJoinFilter(criteriaBuilder, contingencyLimitViolation, filter));
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    default void addPredicate(CriteriaBuilder criteriaBuilder,
                              Root<PreContingencyLimitViolationEntity> path,
                              List<Predicate> predicates,
                              FilterDTO filter) {

      /*  String fieldName = switch (filter.column()) {
            case SUBJECT_ID -> "subjectId";
            default -> throw new UnsupportedOperationException("This method should be called for parent filters only");
        };

        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, fieldName);*/
    }

    default void addJoinFilter(CriteriaBuilder criteriaBuilder,
                               Join<?, ?> joinPath,
                               FilterDTO filter) {
        String fieldName;
        String subFieldName = null;

        switch (filter.column()) {
            case SUBJECT_ID -> fieldName = "subjectId";
            case LIMIT_TYPE -> fieldName = "limitType";
            case LIMIT_NAME -> fieldName = "limitName";
            case SIDE -> fieldName = "side";
            default -> throw new UnsupportedOperationException("This method should be called for nested filters only");
        }

        CriteriaUtils.addJoinFilter(criteriaBuilder, joinPath, filter, fieldName, subFieldName);
    }

    default boolean isParentFilter(FilterDTO filter) {
        //return List.of(FilterDTO.FilterColumn.SUBJECT_ID).contains(filter.column());
        return false;
    }
}
