/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.security.LimitViolationType;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * @author Florent MILLOT <florent.millot@rte-france.com>
 */
@Repository
public interface ContingencyLimitViolationRepository extends JpaRepository<ContingencyLimitViolationEntity, UUID> {
    @Modifying
    @Query(value = "DELETE FROM contingency_limit_violation WHERE contingency_uuid IN ?1", nativeQuery = true)
    void deleteAllByContingencyUuidIn(Set<UUID> uuids);

    @Query(value = "SELECT distinct c.limitType from ContingencyLimitViolationEntity as c " +
            "where c.subjectLimitViolation.result.id = :resultUuid AND c.limitType != ''" +
            "order by c.limitType")
    List<LimitViolationType> findLimitTypes(UUID resultUuid);

    @Query(value = "SELECT distinct c.side from ContingencyLimitViolationEntity as c " +
            "where c.subjectLimitViolation.result.id = :resultUuid AND c.side != ''" +
            "order by c.side")
    List<ThreeSides> findBranchSides(UUID resultUuid);
}
