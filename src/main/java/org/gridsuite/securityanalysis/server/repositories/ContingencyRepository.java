/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.iidm.network.Branch;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.LimitViolationType;
import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collection;
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
            addPredicate(criteriaBuilder, root, predicates, List.of(resultUuid), "result", "id");
            if (contingencyId != null) {
                addPredicate(criteriaBuilder, root, predicates, List.of(contingencyId), "contingencyId", null);
            }
            if (status != null) {
                addPredicate(criteriaBuilder, root, predicates, List.of(status), "status", null);
            }

            // join fetch contingencyLimitViolation table
            Join<Object, Object> contingencyLimitViolation;
            // pageable makes a count request which should only count contingency results, not joined rows
            if (!currentQueryIsCountRecords(query)) {
                contingencyLimitViolation = (Join<Object, Object>) root.fetch("contingencyLimitViolations", JoinType.LEFT);
                // criteria in contingencyLimitViolationEntity
                if (subjectId != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("subjectLimitViolation").get("subjectId"), subjectId));
                }
                if (limitType != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("limitType"), limitType));
                }
                if (limitName != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("limitName"), limitName));
                }
                if (side != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("side"), side));
                }
                if (acceptableDuration != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("acceptableDuration"), acceptableDuration));
                }
                if (limit != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("limit"), limit));
                }
                if (limitReduction != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("limitReduction"), limitReduction));
                }
                if (value != null) {
                    contingencyLimitViolation.on(criteriaBuilder.equal(contingencyLimitViolation.get("value"), value));
                }
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private static void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     Collection<?> collection,
                                     String fieldName,
                                     String subFieldName) {
        if (!CollectionUtils.isEmpty(collection)) {
            Expression<?> expression = subFieldName == null ? path.get(fieldName) : path.get(fieldName).get(subFieldName);
            var predicate = collection.stream()
                .map(id -> criteriaBuilder.equal(expression, id))
                .toArray(Predicate[]::new);
            predicates.add(criteriaBuilder.or(predicate));
        }
    }

    private static boolean currentQueryIsCountRecords(CriteriaQuery<?> criteriaQuery) {
        return criteriaQuery.getResultType() == Long.class || criteriaQuery.getResultType() == long.class;
    }
}
