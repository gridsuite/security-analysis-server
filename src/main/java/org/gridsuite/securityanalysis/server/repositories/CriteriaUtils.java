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

    public static <T> void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     FilterDTO filter,
                                     String fieldName) {
        addPredicate(criteriaBuilder, path, predicates, filter, fieldName, null);
    }

    public static <T> void addPredicate(CriteriaBuilder criteriaBuilder,
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
    public static <T> void addJoinFilter(CriteriaBuilder criteriaBuilder,
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
    private static <T> Predicate filterToPredicate(CriteriaBuilder criteriaBuilder,
                                                Path<?> path,
                                                FilterDTO filter,
                                                String fieldName,
                                                String subFieldName) {
        // expression targets field to filter on
        Expression<?> expression = subFieldName == null ? path.get(fieldName) : path.get(fieldName).get(subFieldName);

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
    private static Predicate filterToAtomicPredicate(CriteriaBuilder criteriaBuilder, Expression expression, FilterDTO filter, Object value) {
        if (filter.dataType().equals(FilterDTO.DataType.TEXT)) {
            String filterValue = (String) value;
            if (filter.type().equals(FilterDTO.Type.STARTS_WITH)) {
                return criteriaBuilder.like(expression, filterValue + "%");
            } else {
                return criteriaBuilder.like(expression, "%" + filterValue + "%");
            }
        }

        throw new UnsupportedOperationException("Not implemented");
    }
}
