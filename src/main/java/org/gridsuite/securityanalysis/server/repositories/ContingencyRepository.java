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
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface ContingencyRepository extends CommonLimitViolationRepository<ContingencyEntity>, JpaRepository<ContingencyEntity, UUID>, JpaSpecificationExecutor<ContingencyEntity> {
    @Override
    default void addPredicate(CriteriaBuilder criteriaBuilder,
                                      Root<ContingencyEntity> path,
                                      List<Predicate> predicates,
                                      ResourceFilterDTO filter) {

        String fieldName = switch (filter.column()) {
            case CONTINGENCY_ID -> "contingencyId";
            case STATUS -> "status";
            default -> throw new UnsupportedOperationException("This method should be called for parent filters only");
        };

        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, fieldName);
    }

    @Override
    default void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      ResourceFilterDTO filter) {
        String dotSeparatedFields = switch (filter.column()) {
            case SUBJECT_ID -> "subjectLimitViolation.subjectId";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case SIDE -> "side";
            default -> throw new UnsupportedOperationException("This method should be called for nested filters only");
        };

        CriteriaUtils.addJoinFilter(criteriaBuilder, joinPath, filter, dotSeparatedFields);
    }

    @Override
    default boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ResourceFilterDTO.Column.CONTINGENCY_ID, ResourceFilterDTO.Column.STATUS).contains(filter.column());
    }
}
