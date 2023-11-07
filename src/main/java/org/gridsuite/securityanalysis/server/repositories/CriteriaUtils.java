/**
 * Copyright (c) 2023, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.springframework.data.jpa.repository.query.EscapeCharacter;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.List;
/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

public final class CriteriaUtils {
    private CriteriaUtils() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     ResourceFilterDTO filter,
                                     String fieldName) {
        Predicate predicate = filterToPredicate(criteriaBuilder, path, filter, fieldName);
        if (predicate != null) {
            predicates.add(predicate);
        }
    }

    /**
     * returns predicate depending on filter.value() type
     * if it's a Collection, it will use "OR" operator between each value
     */
    private static Predicate filterToPredicate(CriteriaBuilder criteriaBuilder,
                                                Path<?> path,
                                                ResourceFilterDTO filter,
                                                String field) {
        // expression targets field to filter on
        Expression<String> expression = path.get(field);

        // collection values are filtered with "or" operator
        if (filter.value() instanceof Collection<?> filterCollection) {
            if (CollectionUtils.isEmpty(filterCollection)) {
                return null;
            }
            return criteriaBuilder.or(
                filterCollection.stream().map(value ->
                    filterToAtomicPredicate(criteriaBuilder, expression, filter, value)
                ).toArray(Predicate[]::new)
            );
        } else {
            return filterToAtomicPredicate(criteriaBuilder, expression, filter, filter.value());
        }
    }

    /**
     * returns atomic predicate depending on filter.dataType() and filter.type()
     */
    private static Predicate filterToAtomicPredicate(CriteriaBuilder criteriaBuilder, Expression<?> expression, ResourceFilterDTO filter, Object value) {
        if (ResourceFilterDTO.DataType.TEXT == filter.dataType()) {
            String stringValue = (String) value;
            String escapedFilterValue = EscapeCharacter.DEFAULT.escape(stringValue);
            if (escapedFilterValue == null) {
                throw new UnsupportedOperationException("Filter text values can not be null");
            }
            // this makes equals query work with enum values
            Expression<String> stringExpression = expression.as(String.class);
            return switch (filter.type()) {
                case CONTAINS -> criteriaBuilder.like(criteriaBuilder.upper(stringExpression), "%" + escapedFilterValue.toUpperCase() + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
                case STARTS_WITH -> criteriaBuilder.like(criteriaBuilder.upper(stringExpression), escapedFilterValue.toUpperCase() + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
                case EQUALS -> criteriaBuilder.equal(criteriaBuilder.upper(stringExpression), stringValue.toUpperCase());
            };
        } else {
            throw new UnsupportedOperationException("Not implemented");
        }
    }
}
