/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.security.LimitViolationType;
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

    @Modifying
    @Query(value = "DELETE FROM pre_contingency_limit_violation WHERE result_id = ?1", nativeQuery = true)
    void deleteAllByResultId(UUID resultId);

    @Query(value = "SELECT distinct pc.limitType from PreContingencyLimitViolationEntity as pc " +
        "where pc.subjectLimitViolation.result.id = :resultUuid AND pc.limitType != ''" +
        "order by pc.limitType")
    List<LimitViolationType> findLimitTypes(UUID resultUuid);

    @Query(value = "SELECT distinct pc.side from PreContingencyLimitViolationEntity as pc " +
        "where pc.subjectLimitViolation.result.id = :resultUuid AND pc.side != ''" +
        "order by pc.side")
    List<ThreeSides> findBranchSides(UUID resultUuid);
}
