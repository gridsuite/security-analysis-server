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
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.*;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface ContingencyRepository extends CommonLimitViolationRepository<ContingencyEntity>, JpaRepository<ContingencyEntity, UUID>, JpaSpecificationExecutor<ContingencyEntity> {
    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<ContingencyEntity> findAllWithContingencyLimitViolationsByUuidIn(List<UUID> contingencyUuids);

    @Override
    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<ContingencyEntity> findAll(Specification<ContingencyEntity> spec);

    List<ContingencyEntity> findAllByUuidIn(List<UUID> uuids);

    @Override
    default void addPredicate(CriteriaBuilder criteriaBuilder,
                              Path<?> path,
                              List<Predicate> predicates,
                              ResourceFilterDTO filter) {

        String fieldName = switch (filter.column()) {
            case CONTINGENCY_ID -> "contingencyId";
            case STATUS -> "status";
            case SUBJECT_ID -> "subjectLimitViolation.subjectId";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case SIDE -> "side";
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

    @Override
    default Path<?> getFilterPath(Root<?> root) {
        return root.get("contingencyLimitViolations");
    }
}
