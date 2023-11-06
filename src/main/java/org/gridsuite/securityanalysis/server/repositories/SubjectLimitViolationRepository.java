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
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

import static java.util.function.Predicate.not;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

@Repository
public interface SubjectLimitViolationRepository extends CommonLimitViolationRepository<SubjectLimitViolationEntity>, JpaRepository<SubjectLimitViolationEntity, UUID>, JpaSpecificationExecutor<SubjectLimitViolationEntity> {
    @Override
    default Specification<SubjectLimitViolationEntity> getLimitViolationsSpecifications(
        List<UUID> subjectLimitViolationsUuid,
        List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            // join fetch contingencyLimitViolation table
            Join<Object, Object> contingencyLimitViolation = (Join<Object, Object>) root.fetch(getNestedObjectPath(), JoinType.LEFT);
            contingencyLimitViolation.fetch("contingency", JoinType.LEFT);

            // criteria in contingencyLimitViolationEntity
            // user filters
            filters.stream().filter(not(this::isParentFilter))
                .forEach(filter -> addJoinFilter(criteriaBuilder, contingencyLimitViolation, filter));

            // filter on subjectLimitViolationUuid
            return root.get("id").in(subjectLimitViolationsUuid);
        };
    }

    @Override
    default void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     ResourceFilterDTO filter) {

        String dotSeparatedFields = switch (filter.column()) {
            case CONTINGENCY_ID -> "contingency.contingencyId";
            case STATUS -> "contingency.status";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case SIDE -> "side";
            case SUBJECT_ID -> "subjectId";
        };

        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, dotSeparatedFields);
    }

    @Override
    default void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                      Join<?, ?> joinPath,
                                      ResourceFilterDTO filter) {
        String dotSeparatedFields = switch (filter.column()) {
            case CONTINGENCY_ID -> "contingency.contingencyId";
            case STATUS -> "contingency.status";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case SIDE -> "side";
            default -> throw new UnsupportedOperationException("This method should be called for nested filters only");
        };

        CriteriaUtils.addJoinFilter(criteriaBuilder, joinPath, filter, dotSeparatedFields);
    }

    @Override
    default boolean isParentFilter(ResourceFilterDTO filter) {
        return ResourceFilterDTO.Column.SUBJECT_ID == filter.column();
    }

    @Override
    default String getNestedObjectPath() {
        return "contingencyLimitViolations";
    }
}
