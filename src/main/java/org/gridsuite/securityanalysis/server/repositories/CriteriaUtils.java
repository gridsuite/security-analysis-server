package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
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
                                     T filter,
                                     String fieldName) {
        addPredicate(criteriaBuilder, path, predicates, filter, fieldName, null);
    }

    public static <T> void addPredicate(CriteriaBuilder criteriaBuilder,
                                     Path<?> path,
                                     List<Predicate> predicates,
                                     T filter,
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
                                         T filter,
                                         String fieldName) {
        addJoinFilter(criteriaBuilder, joinPath, filter, fieldName, null);
    }

    // add condition on <joinPath>
    public static <T> void addJoinFilter(CriteriaBuilder criteriaBuilder,
                                         Join<?, ?> joinPath,
                                         T filter,
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

    private static <T> Predicate filterToPredicate(CriteriaBuilder criteriaBuilder,
                                                Path<?> joinPath,
                                                T filter,
                                                String fieldName,
                                                String subFieldName) {
        if (filter == null) {
            return null;
        }

        // expression targets field to filter on
        Expression<?> expression = subFieldName == null ? joinPath.get(fieldName) : joinPath.get(fieldName).get(subFieldName);

        // collection values are filtered with "or" operator
        if (filter instanceof Collection<?> filterCollection) {
            if (CollectionUtils.isEmpty(filterCollection)) {
                return null;
            }
            return criteriaBuilder.or(
                filterCollection.stream().map(value ->
                    criteriaBuilder.equal(expression, value)
                ).toArray(Predicate[]::new)
            );
        } else {
            return criteriaBuilder.equal(expression, filter);
        }
    }
}
