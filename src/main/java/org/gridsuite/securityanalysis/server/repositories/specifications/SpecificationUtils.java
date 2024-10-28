/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package org.gridsuite.securityanalysis.server.repositories.specifications;

import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Root;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.jetbrains.annotations.NotNull;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.data.jpa.repository.query.EscapeCharacter;

import java.util.Collection;
import java.util.List;
import java.util.Objects;

import static org.springframework.data.jpa.domain.Specification.anyOf;
import static org.springframework.data.jpa.domain.Specification.not;

/**
 * Utility class to create Spring Data JPA Specification (Spring interface for JPA Criteria API).
 *
 * @author Kevin Le Saulnier <kevin.lesaulnier@rte-france.com>
 */
public final class SpecificationUtils {

    public static final String FIELD_SEPARATOR = ".";

    // Utility class, so no constructor
    private SpecificationUtils() {
    }

    // we use .as(String.class) to be able to works on enum fields
    public static <X> Specification<X> equals(String field, String value) {
        return (root, cq, cb) -> cb.equal(cb.upper(getColumnPath(root, field)).as(String.class), value.toUpperCase());
    }

    public static <X> Specification<X> notEqual(String field, String value) {
        return (root, cq, cb) -> cb.notEqual(getColumnPath(root, field), value);
    }

    public static <X> Specification<X> contains(String field, String value) {
        return (root, cq, cb) -> cb.like(cb.upper(getColumnPath(root, field)), "%" + EscapeCharacter.DEFAULT.escape(value).toUpperCase() + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
    }

    public static <X> Specification<X> startsWith(String field, String value) {
        return (root, cq, cb) -> cb.like(cb.upper(getColumnPath(root, field)), EscapeCharacter.DEFAULT.escape(value).toUpperCase() + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
    }

    public static <X> Specification<X> notEqual(String field, Double value, Double tolerance) {
        return (root, cq, cb) -> {
            Expression<Double> doubleExpression = getColumnPath(root, field).as(Double.class);
            return cb.or(
                    cb.greaterThan(doubleExpression, value + tolerance),
                    cb.lessThanOrEqualTo(doubleExpression, value)
            );
        };
    }

    public static <X> Specification<X> lessThanOrEqual(String field, Double value, Double tolerance) {
        return (root, cq, cb) -> {
            Expression<Double> doubleExpression = getColumnPath(root, field).as(Double.class);
            return cb.lessThanOrEqualTo(doubleExpression, value + tolerance);
        };
    }

    public static <X> Specification<X> greaterThanOrEqual(String field, Double value, Double tolerance) {
        return (root, cq, cb) -> {
            Expression<Double> doubleExpression = getColumnPath(root, field).as(Double.class);
            return cb.greaterThanOrEqualTo(doubleExpression, value - tolerance);
        };
    }

    public static <X> Specification<X> isNotEmpty(String field) {
        return (root, cq, cb) -> cb.isNotEmpty(getColumnPath(root, field));
    }

    public static <X> Specification<X> distinct() {
        return (root, cq, cb) -> {
            // to select distinct result, we need to set a "criteria query" param
            // we don't need to return any predicate here
            cq.distinct(true);
            return null;
        };
    }

    public static <X> Specification<X> appendFiltersToSpecification(Specification<X> specification, List<ResourceFilterDTO> resourceFilters) {
        Objects.requireNonNull(specification);

        if (resourceFilters == null || resourceFilters.isEmpty()) {
            return specification;
        }

        Specification<X> completedSpecification = specification;

        for (ResourceFilterDTO resourceFilter : resourceFilters) {
            if (resourceFilter.dataType() == ResourceFilterDTO.DataType.TEXT) {
                completedSpecification = appendTextFilterToSpecification(completedSpecification, resourceFilter);
            } else if (resourceFilter.dataType() == ResourceFilterDTO.DataType.NUMBER) {
                completedSpecification = appendNumberFilterToSpecification(completedSpecification, resourceFilter);
            }
        }

        return completedSpecification;
    }

    @NotNull
    private static <X> Specification<X> appendTextFilterToSpecification(Specification<X> specification, ResourceFilterDTO resourceFilter) {
        Specification<X> completedSpecification = specification;

        switch (resourceFilter.type()) {
            case EQUALS -> {
                // this type can manage one value or a list of values (with OR)
                if (resourceFilter.value() instanceof Collection<?> valueList) {
                    completedSpecification = completedSpecification.and(anyOf(valueList.stream().map(value -> SpecificationUtils.<X>equals(resourceFilter.column(), value.toString())).toList()));
                } else if (resourceFilter.value() == null) {
                    // if the value is null, we build an impossible specification (trick to remove later on ?)
                    completedSpecification = completedSpecification.and(not(completedSpecification));
                } else {
                    completedSpecification = completedSpecification.and(equals(resourceFilter.column(), resourceFilter.value().toString()));
                }
            }
            case CONTAINS ->
                completedSpecification = completedSpecification.and(contains(resourceFilter.column(), resourceFilter.value().toString()));
            case STARTS_WITH ->
                completedSpecification = completedSpecification.and(startsWith(resourceFilter.column(), resourceFilter.value().toString()));
            default -> throw new IllegalArgumentException("The filter type " + resourceFilter.type() + " is not supported with the data type " + resourceFilter.dataType());
        }

        return completedSpecification;
    }

    @NotNull
    private static <X> Specification<X> appendNumberFilterToSpecification(Specification<X> specification, ResourceFilterDTO resourceFilter) {
        String value = resourceFilter.value().toString();
        return createNumberPredicate(specification, resourceFilter, value);
    }

    private static <X> Specification<X> createNumberPredicate(Specification<X> specification, ResourceFilterDTO resourceFilter, String value) {
        String[] splitValue = value.split("\\.");
        int numberOfDecimalAfterDot = 0;
        if (splitValue.length > 1) {
            numberOfDecimalAfterDot = splitValue[1].length();
        }
        final double tolerance = Math.pow(10, -numberOfDecimalAfterDot); // tolerance for comparison
        Double valueDouble = Double.valueOf(value);
        return switch (resourceFilter.type()) {
            case NOT_EQUAL -> specification.and(notEqual(resourceFilter.column(), valueDouble, tolerance));
            case LESS_THAN_OR_EQUAL ->
                    specification.and(lessThanOrEqual(resourceFilter.column(), valueDouble, tolerance));
            case GREATER_THAN_OR_EQUAL ->
                    specification.and(greaterThanOrEqual(resourceFilter.column(), valueDouble, tolerance));
            default ->
                    throw new IllegalArgumentException("The filter type " + resourceFilter.type() + " is not supported with the data type " + resourceFilter.dataType());
        };
    }

    /**
     * This method allow to query eventually dot separated fields with the Criteria API
     * Ex : from 'fortescueCurrent.positiveMagnitude' we create the query path
     * root.get("fortescueCurrent").get("positiveMagnitude") to access to the correct nested field
     *
     * @param root               the root entity
     * @param dotSeparatedFields dot separated fields (can be only one field without any dot)
     * @param <X>                the entity type referenced by the root
     * @param <Y>                the type referenced by the path
     * @return path for the query
     */
    private static <X, Y> Path<Y> getColumnPath(Root<X> root, String dotSeparatedFields) {
        if (dotSeparatedFields.contains(SpecificationUtils.FIELD_SEPARATOR)) {
            String[] fields = dotSeparatedFields.split("\\.");
            Path<Y> path = root.get(fields[0]);
            for (int i = 1; i < fields.length; i++) {
                path = path.get(fields[i]);
            }
            return path;
        } else {
            return root.get(dotSeparatedFields);
        }
    }
}
