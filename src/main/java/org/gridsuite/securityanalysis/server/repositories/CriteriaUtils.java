package org.gridsuite.securityanalysis.server.repositories;

import jakarta.persistence.criteria.*;
import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.springframework.data.jpa.repository.query.EscapeCharacter;
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
                                     ResourceFilterDTO filter,
                                     String dotSeparatedFields) {
        Predicate predicate = filterToPredicate(criteriaBuilder, path, filter, dotSeparatedFields);
        if (predicate != null) {
            predicates.add(predicate);
        }
    }

    // add condition on <joinPath>
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
                                                String dotSeparatedField) {
        // expression targets field to filter on
        Expression<String> expression = getColumnPath(path, dotSeparatedField);

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
            String filterValue = (String) value;
            // this makes equals query work with enum values
            Expression<String> stringExpression = expression.as(String.class);
            return switch (filter.type()) {
                case CONTAINS -> criteriaBuilder.like(stringExpression, "%" + EscapeCharacter.DEFAULT.escape(filterValue) + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
                case STARTS_WITH -> criteriaBuilder.like(stringExpression, EscapeCharacter.DEFAULT.escape(filterValue) + "%", EscapeCharacter.DEFAULT.getEscapeCharacter());
                case EQUALS -> criteriaBuilder.equal(stringExpression, filterValue);
            };
        } else {
            throw new UnsupportedOperationException("Not implemented");
        }
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
