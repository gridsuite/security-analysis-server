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

    public static void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                     Join<?, ?> joinPath,
                                     ResourceFilterDTO filter,
                                     String dotSeparatedFields) {
        Predicate predicate = filterToPredicate(criteriaBuilder, joinPath, filter, dotSeparatedFields);
        if (predicate != null) {
            joinPath.on(predicate);
        }
    }

    public static boolean currentQueryIsCountRecords(CriteriaQuery<?> criteriaQuery) {
        return criteriaQuery.getResultType() == Long.class || criteriaQuery.getResultType() == long.class;
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
                            filterToAtomicPredicate(criteriaBuilder, path, expression, filter, value)
                    ).toArray(Predicate[]::new)
            );
        } else {
            return filterToAtomicPredicate(criteriaBuilder, path, expression, filter, filter.value());
        }
    }

    /**
     * returns atomic predicate depending on filter.dataType() and filter.type()
     */
    private static Predicate filterToAtomicPredicate(CriteriaBuilder criteriaBuilder, Path<?> path, Expression<String> expression, ResourceFilterDTO filter, Object value) {

        if (ResourceFilterDTO.DataType.TEXT == filter.dataType()) {
            String stringValue = (String) value;
            String escapedFilterValue = EscapeCharacter.DEFAULT.escape(stringValue);
            if (escapedFilterValue == null) {
                throw new UnsupportedOperationException("Filter text values can not be null");
            }
            // this makes equals query work with enum values
            Expression<String> stringExpression = expression.as(String.class);
            return switch (filter.type()) {
                case CONTAINS ->
                        criteriaBuilder.like(criteriaBuilder.upper(stringExpression), "%" + escapedFilterValue.toUpperCase() + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
                case STARTS_WITH ->
                        criteriaBuilder.like(criteriaBuilder.upper(stringExpression), escapedFilterValue.toUpperCase() + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
                case EQUALS ->
                        criteriaBuilder.equal(criteriaBuilder.upper(stringExpression), stringValue.toUpperCase());
                default ->
                        throw new UnsupportedOperationException("This type of filter is not supported for text data type");
            };
        }

        if (ResourceFilterDTO.DataType.NUMBER == filter.dataType()) {
            return switch (filter.type()) {
                case NOT_EQUAL -> criteriaBuilder.notEqual(expression, value);
                case LESS_THAN_OR_EQUAL ->
                        criteriaBuilder.lessThanOrEqualTo(getColumnPath(path, filter.column().columnName()), Double.valueOf((String) value));
                case GREATER_THAN_OR_EQUAL ->
                        criteriaBuilder.greaterThanOrEqualTo(getColumnPath(path, filter.column().columnName()), Double.valueOf((String) value));
                default ->
                        throw new UnsupportedOperationException("This type of filter is not supported for number data type");
            };
        }
        throw new IllegalArgumentException("The filter type " + filter.type() + " is not supported with the data type " + filter.dataType());

    }

    /**
     * This method allow to query eventually dot separated fields with the Criteria API
     * Ex : from 'fortescueCurrent.positiveMagnitude' we create the query path
     * path.get("fortescueCurrent").get("positiveMagnitude") to access to the correct nested field
     *
     * @param originPath         the origin path
     * @param dotSeparatedFields dot separated fields (can be only one field without any dot)
     * @param <X>                the entity type referenced by the origin path
     * @param <Y>                the type referenced by the path
     * @return path for the query
     */
    private static <X, Y> Path<Y> getColumnPath(Path<X> originPath, String dotSeparatedFields) {
        if (dotSeparatedFields.contains(".")) {
            String[] fields = dotSeparatedFields.split("\\.");
            Path<Y> path = originPath.get(fields[0]);
            for (int i = 1; i < fields.length; i++) {
                path = path.get(fields[i]);
            }
            return path;
        } else {
            return originPath.get(dotSeparatedFields);
        }
    }

}
