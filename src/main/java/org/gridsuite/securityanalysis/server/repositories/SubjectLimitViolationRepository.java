/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
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
public interface SubjectLimitViolationRepository extends CommonLimitViolationRepository<SubjectLimitViolationEntity>, JpaRepository<SubjectLimitViolationEntity, UUID>, JpaSpecificationExecutor<SubjectLimitViolationEntity> {
    @EntityGraph(attributePaths = {"contingencyLimitViolations", "contingencyLimitViolations.contingency"}, type = EntityGraph.EntityGraphType.LOAD)
    List<SubjectLimitViolationEntity> findAllWithContingencyLimitViolationsByIdIn(List<UUID> subjectLimitViolationUuids);

    @Override
    default void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Root<SubjectLimitViolationEntity> path,
                                     List<Predicate> predicates,
                                     ResourceFilterDTO filter) {

        if (ResourceFilterDTO.Column.SUBJECT_ID != filter.column()) {
            throw new UnsupportedOperationException("This method should be called for parent filters only");
        } else {
            CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, "subjectId");
        }
    }
}
