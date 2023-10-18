package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.FilterDTO;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.List;

public final class CriteriaUtils {
    private CriteriaUtils() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    public static void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     FilterDTO filter,
                                     String fieldName) {
        addPredicate(criteriaBuilder, path, predicates, filter, fieldName, null);
    }

    public static void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     FilterDTO filter,
                                     String fieldName,
                                     String subFieldName) {
        Predicate predicate = filterToPredicate(criteriaBuilder, path, filter, fieldName, subFieldName);
        if (predicate != null) {
            predicates.add(predicate);
        }
    }

    // add condition on <joinPath>
    public static void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                         Join<?, ?> joinPath,
                                         FilterDTO filter,
                                         String fieldName,
                                         String subFieldName) {
        Predicate predicate = filterToPredicate(criteriaBuilder, joinPath, filter, fieldName, subFieldName);
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
                                                FilterDTO filter,
                                                String fieldName,
                                                String subFieldName) {
        // expression targets field to filter on
        Expression<String> expression = subFieldName == null ? path.get(fieldName) : path.get(fieldName).get(subFieldName);

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
    private static Predicate filterToAtomicPredicate(CriteriaBuilder criteriaBuilder, Expression<?> expression, FilterDTO filter, Object value) {
        if (filter.dataType().equals(FilterDTO.DataType.TEXT)) {
            String filterValue = (String) value;
            // this makes contains/startsWith query work with enum values
            Expression<String> stringExpression = expression.as(String.class);
            return switch (filter.type()) {
                case CONTAINS -> criteriaBuilder.like(stringExpression, "%" + filterValue + "%");
                case STARTS_WITH -> criteriaBuilder.like(stringExpression, filterValue + "%");
                case EQUALS -> criteriaBuilder.equal(stringExpression, filterValue);
            };
        }

        throw new UnsupportedOperationException("Not implemented");
    }
}
