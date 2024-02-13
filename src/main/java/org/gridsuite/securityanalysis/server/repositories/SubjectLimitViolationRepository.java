/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.*;
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

    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<SubjectLimitViolationEntity> findAllWithContingencyContingencyLimitViolationsByIdIn(List<UUID> uuids);

    List<SubjectLimitViolationEntity> findAllByIdIn(List<UUID> uuids);

    List<SubjectLimitViolationEntity> findAllByResultId(UUID resultUuid);

    @Override
    default String columnToDotSeparatedField(ResourceFilterDTO.Column column) {
        return switch (column) {
            case CONTINGENCY_ID -> "contingency.contingencyId";
            case STATUS -> "contingency.status";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case SIDE -> "side";
            case SUBJECT_ID -> "subjectId";
            default -> throw new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_FILTER);
        };
    }

    @Override
    default boolean isParentFilter(ResourceFilterDTO filter) {
        return filter.column().equals(ResourceFilterDTO.Column.SUBJECT_ID);
    }

    @Override
    default void addSpecificFilter(Root<SubjectLimitViolationEntity> root, CriteriaBuilder criteriaBuilder, List<Predicate> predicates) {
        predicates.add(criteriaBuilder.isNotEmpty(root.get("contingencyLimitViolations")));
    }

    interface EntityId {
        UUID getId();
    }

    @Override
    default String getIdFieldName() {
        return "id";
    }

    @Modifying
    @Query(value = "DELETE FROM subject_limit_violation WHERE result_id = ?1", nativeQuery = true)
    void deleteAllByResultId(UUID resultId);
}
