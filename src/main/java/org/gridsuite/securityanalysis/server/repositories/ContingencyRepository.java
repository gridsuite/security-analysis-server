/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.loadflow.LoadFlowResult;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.util.SecurityAnalysisException;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.*;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface ContingencyRepository extends /*CommonLimitViolationRepository<ContingencyEntity>, */JpaRepository<ContingencyEntity, UUID>, JpaSpecificationExecutor<ContingencyEntity> {
    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<ContingencyEntity> findAll(Specification<ContingencyEntity> spec);

    @EntityGraph(attributePaths = {"contingencyElements"}, type = EntityGraph.EntityGraphType.LOAD)
    List<ContingencyEntity> findAllWithContingencyElementsByUuidIn(List<UUID> uuids);

    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<ContingencyEntity> findAllWithContingencyLimitViolationsByUuidIn(List<UUID> uuids);

    List<ContingencyEntity> findAllByUuidIn(List<UUID> uuids);

    List<ContingencyEntity> findAllByResultId(UUID resultId);

    @Query(value = "SELECT uuid FROM ContingencyEntity WHERE result.id = ?1")
    Set<UUID> findAllUuidsByResultId(UUID resultId);

    @Modifying
    @Query(value = "DELETE FROM contingency WHERE result_id = ?1", nativeQuery = true)
    void deleteAllByResultId(UUID resultId);

    @Modifying
    @Query(value = "DELETE FROM contingency_entity_contingency_elements WHERE contingency_entity_uuid IN ?1", nativeQuery = true)
    void deleteAllContingencyElementsByContingencyUuidIn(Set<UUID> uuids);
//
//    @Override
//    default String columnToDotSeparatedField(ResourceFilterDTO.Column column) {
//        return switch (column) {
//            case CONTINGENCY_ID -> "contingencyId";
//            case STATUS -> "status";
//            case SUBJECT_ID -> "subjectLimitViolation.subjectId";
//            case LIMIT_TYPE -> "limitType";
//            case LIMIT_NAME -> "limitName";
//            case SIDE -> "side";
//            default -> throw new SecurityAnalysisException(SecurityAnalysisException.Type.INVALID_FILTER);
//        };
//    }
//
    default boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ResourceFilterDTO.Column.CONTINGENCY_ID, ResourceFilterDTO.Column.STATUS).contains(filter.column());
    }
//
//    @Override
//    default void addSpecificFilter(Root<ContingencyEntity> root, CriteriaBuilder criteriaBuilder, List<Predicate> predicates) {
//        predicates.add(criteriaBuilder.or(
//                criteriaBuilder.isNotEmpty(root.get("contingencyLimitViolations")),
//                criteriaBuilder.notEqual(root.get("status"), LoadFlowResult.ComponentResult.Status.CONVERGED.toString())
//        ));
//    }
//
    interface EntityUuid {
        UUID getUuid();
    }
//
//    @Override
//    default String getIdFieldName() {
//        return "uuid";
//    }

}
