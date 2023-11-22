/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
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
public interface ContingencyRepository extends CommonLimitViolationRepository<ContingencyEntity>, JpaRepository<ContingencyEntity, UUID>, JpaSpecificationExecutor<ContingencyEntity> {
    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<ContingencyEntity> findAll(Specification<ContingencyEntity> spec);

    @EntityGraph(attributePaths = {"contingencyElements"}, type = EntityGraph.EntityGraphType.LOAD)
    List<ContingencyEntity> findAllWithContingencyElementsByUuidIn(List<UUID> uuids);

    List<ContingencyEntity> findAllByUuidIn(List<UUID> uuids);

    @Override
    default String columnToDotSeparatedField(ResourceFilterDTO.Column column) {
        return switch (column) {
            case CONTINGENCY_ID -> "contingencyId";
            case STATUS -> "status";
            case SUBJECT_ID -> "subjectLimitViolation.subjectId";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case SIDE -> "side";
            default -> throw new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_FILTER);
        };
    }

    @Override
    default boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ResourceFilterDTO.Column.CONTINGENCY_ID, ResourceFilterDTO.Column.STATUS).contains(filter.column());
    }

    interface EntityUuid {
        UUID getUuid();
    }

    @Override
    default String getIdFieldName() {
        return "uuid";
    }

}
