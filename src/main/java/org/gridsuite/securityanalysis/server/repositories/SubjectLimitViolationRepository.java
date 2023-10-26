/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.List;
import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

public interface SubjectLimitViolationRepository extends CommonLimitViolationRepository<SubjectLimitViolationEntity>, JpaRepository<SubjectLimitViolationEntity, UUID>, JpaSpecificationExecutor<SubjectLimitViolationEntity> {
    Page<SubjectLimitViolationEntity> findAll(Specification<SubjectLimitViolationEntity> specification, Pageable pageable);

    default void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Root<SubjectLimitViolationEntity> path,
                                     List<Predicate> predicates,
                                     ResourceFilterDTO filter) {

        String fieldName = switch (filter.column()) {
            case SUBJECT_ID -> "subjectId";
            default -> throw new UnsupportedOperationException("This method should be called for parent filters only");
        };

        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, fieldName);
    }

    default void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      ResourceFilterDTO filter) {
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

    default boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ResourceFilterDTO.FilterColumn.SUBJECT_ID).contains(filter.column());
    }
}
