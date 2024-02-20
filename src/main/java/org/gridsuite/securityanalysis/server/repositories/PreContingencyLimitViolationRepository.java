/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.*;

import java.util.List;
import java.util.UUID;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
public interface PreContingencyLimitViolationRepository extends JpaRepository<PreContingencyLimitViolationEntity, UUID>, JpaSpecificationExecutor<PreContingencyLimitViolationEntity> {
    @EntityGraph(attributePaths = {"subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<PreContingencyLimitViolationEntity> findAll(Specification<PreContingencyLimitViolationEntity> specification, Sort sort);

    default boolean isParentFilter(ResourceFilterDTO filter) {
        return !List.of(ResourceFilterDTO.Column.SUBJECT_ID).contains(filter.column());
    }

    default boolean isParentFilter(String filter) {
        return filter.equals("subjectId");
    }

    @Modifying
    @Query(value = "DELETE FROM pre_contingency_limit_violation WHERE result_id = ?1", nativeQuery = true)
    void deleteAllByResultId(UUID resultId);
}
