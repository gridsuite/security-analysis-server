/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import com.powsybl.loadflow.LoadFlowResult;
import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

public interface SubjectLimitViolationRepository extends JpaRepository<SubjectLimitViolationEntity, UUID>, JpaSpecificationExecutor<SubjectLimitViolationEntity> {
    Page<SubjectLimitViolationEntity> findByResultIdOrderBySubjectId(UUID resultUuid, Pageable pageable);

    Page<SubjectLimitViolationEntity> findAll(Specification<SubjectLimitViolationEntity> specification, Pageable pageable);

    static Specification<SubjectLimitViolationEntity> getSpecification(UUID resultUuid) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();
            addPredicate(criteriaBuilder, root, predicates, List.of(resultUuid), "result", "id");
            //addPredicate(criteriaBuilder, root, predicates, List.of("l1", "l3"), "contingencyId", null);
/*
            addPredicate(criteriaBuilder, root, predicates, List.of(LoadFlowResult.ComponentResult.Status.CONVERGED.name()), "status", null);
*/
            Join<Object, Object> contingencyLimitViolation;
            if(!currentQueryIsCountRecords(query)) {
                contingencyLimitViolation = (Join<Object, Object>) root.fetch("contingencyLimitViolations", JoinType.LEFT);
            }

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }

    private static void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Root<SubjectLimitViolationEntity> root,
                                     List<Predicate> predicates,
                                     Collection<?> collection,
                                     String fieldName,
                                     String subFieldName) {
        if (!CollectionUtils.isEmpty(collection)) {
            Expression<?> expression = subFieldName == null ? root.get(fieldName) : root.get(fieldName).get(subFieldName);
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
