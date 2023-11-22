/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.PreContingencyLimitViolationEntity;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static java.util.function.Predicate.not;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */
public interface PreContingencyLimitViolationRepository extends JpaRepository<PreContingencyLimitViolationEntity, UUID>, JpaSpecificationExecutor<PreContingencyLimitViolationEntity> {
    @EntityGraph(attributePaths = {"subjectLimitViolation"}, type = EntityGraph.EntityGraphType.LOAD)
    List<PreContingencyLimitViolationEntity> findAll(Specification<PreContingencyLimitViolationEntity> specification, Sort sort);

  /*  default Specification<PreContingencyLimitViolationEntity> getSpecification(
            UUID resultUuid,
            List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();

            // criteria in preContingencyLimitViolationEntity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // user filters
            List<ResourceFilterDTO> parentFilters = filters.stream().filter(this::isParentFilter).toList();
            parentFilters.forEach(filter -> addPredicate(criteriaBuilder, root.get("subjectLimitViolation"), predicates, filter));

            return criteriaBuilder.and(predicates.toArray(new Predicate[0]));
        };
    }*/

    /**
     * Returns specification depending on {@code filters} <br/>
     * This interface is common for both SubjectLimitViolationRepository and ContingencyRepository
     * except for <i>addPredicate</i> which needs to be implemented
     */
    default Specification<PreContingencyLimitViolationEntity> getParentsSpecifications(
            UUID resultUuid,
            List<ResourceFilterDTO> filters
    ) {
        return (root, query, criteriaBuilder) -> {
            List<Predicate> predicates = new ArrayList<>();
            List<ResourceFilterDTO> childrenFilters = filters.stream().filter(not(this::isParentFilter)).toList();

            // criteria in main entity
            // filter by resultUuid
            predicates.add(criteriaBuilder.equal(root.get("result").get("id"), resultUuid));

            // user filters on main entity
            filters.stream().filter(this::isParentFilter)
                    .forEach(filter -> addPredicate(criteriaBuilder, root, predicates, filter));

            if (!childrenFilters.isEmpty()) {
                // user filters on OneToMany collection - needed here to filter main entities that would have empty collection when filters are applied
                childrenFilters
                        .forEach(filter -> addPredicate(criteriaBuilder, root.get("subjectLimitViolation"), predicates, filter));
            }

            return criteriaBuilder.and(predicates.toArray(Predicate[]::new));
        };
    }

    default void addPredicate(CriteriaBuilder criteriaBuilder,
                              Path<?> path,
                              List<Predicate> predicates,
                              ResourceFilterDTO filter) {

        String fieldName = switch (filter.column()) {
            case SUBJECT_ID -> "subjectId";
            case LIMIT_TYPE -> "limitType";
            case LIMIT_NAME -> "limitName";
            case LIMIT -> "limit";
            case VALUE -> "value";
            case ACCEPTABLE_DURATION -> "acceptableDuration";
            case SIDE -> "side";
            case LOADING -> "loading";
            default -> throw new UnsupportedOperationException("This method should be called for parent filters only");
        };
        CriteriaUtils.addPredicate(criteriaBuilder, path, predicates, filter, fieldName);
    }

    default boolean isParentFilter(ResourceFilterDTO filter) {
        return !List.of(ResourceFilterDTO.Column.SUBJECT_ID).contains(filter.column());
    }

    default boolean isParentFilter(String filter) {
        return filter.equals("subjectId");
    }
}
