/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface SubjectLimitViolationRepository extends CommonLimitViolationRepository<SubjectLimitViolationEntity>, JpaRepository<SubjectLimitViolationEntity, UUID>, JpaSpecificationExecutor<SubjectLimitViolationEntity> {
    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.contingency"}, type = EntityGraph.EntityGraphType.LOAD)
    List<SubjectLimitViolationEntity> findAll(Specification<SubjectLimitViolationEntity> spec);

    List<SubjectLimitViolationEntity> findAllByIdIn(List<UUID> uuids);

    @Override
    default String columnToDotSeparatedField(ResourceFilterDTO.Column column) {
        return switch (column) {
            case CONTINGENCY_ID -> "contingency.contingencyId";
            case STATUS -> "contingency.status";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case SIDE -> "side";
            case SUBJECT_ID -> "subjectId";
        };
    }

    @Override
    default boolean isParentFilter(ResourceFilterDTO filter) {
        return filter.column().equals(ResourceFilterDTO.Column.SUBJECT_ID);
    }

    interface EntityId {
        UUID getId();
    }

    @Override
    default String getIdFieldName() {
        return "id";
    }
}
