/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface ContingencyRepository extends JpaRepository<ContingencyEntity, UUID>, JpaSpecificationExecutor<ContingencyEntity> {
    Page<ContingencyEntity> findAll(Specification<ContingencyEntity> specification, Pageable pageable);

    static Specification<ContingencyEntity> getSpecification(
        UUID resultUuid,
        String contingencyId,
        String status,
        String subjectId,
        LimitViolationType limitType,
        String limitName,
        Branch.Side side,
        Integer acceptableDuration,
        Double limit,
        Double limitReduction,
        Double value
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // criteria in contingencyEntity
            CriteriaUtils.addPredicate(criteriaBuilder, root, predicates, resultUuid, "result", "id");
            CriteriaUtils.addPredicate(criteriaBuilder, root, predicates, contingencyId, "contingencyId");
            CriteriaUtils.addPredicate(criteriaBuilder, root, predicates, status, "status");

            // pageable makes a count request which should only count contingency results, not joined rows
            if (!CriteriaUtils.currentQueryIsCountRecords(query)) {
                // join fetch contingencyLimitViolation table
                Join<Object, Object> contingencyLimitViolation = (Join<Object, Object>) root.fetch("contingencyLimitViolations", JoinType.LEFT);
                // criteria in contingencyLimitViolationEntity
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, subjectId, "subjectLimitViolation", "subjectId");
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, limitType, "limitType");
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, limitName, "limitName");
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, side, "side");
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, acceptableDuration, "acceptableDuration");
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, limit, "limit");
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, limitReduction, "limitReduction");
                CriteriaUtils.addJoinFilter(criteriaBuilder, contingencyLimitViolation, value, "value");
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }


}
