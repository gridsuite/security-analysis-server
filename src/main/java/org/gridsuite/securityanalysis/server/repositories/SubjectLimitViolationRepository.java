/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.*;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface SubjectLimitViolationRepository extends JpaRepository<SubjectLimitViolationEntity, UUID>, JpaSpecificationExecutor<SubjectLimitViolationEntity> {
    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.contingency"}, type = EntityGraph.EntityGraphType.LOAD)
    List<SubjectLimitViolationEntity> findAll(Specification<SubjectLimitViolationEntity> spec);

    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<SubjectLimitViolationEntity> findAllWithContingencyContingencyLimitViolationsByIdIn(List<UUID> uuids);

    List<SubjectLimitViolationEntity> findAllByIdIn(List<UUID> uuids);

    List<SubjectLimitViolationEntity> findAllByResultId(UUID resultUuid);

    interface EntityId {
        UUID getId();
    }

    @Modifying
    @Query(value = "DELETE FROM subject_limit_violation WHERE result_id = ?1", nativeQuery = true)
    void deleteAllByResultId(UUID resultId);
}
