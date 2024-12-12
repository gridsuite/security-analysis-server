-- BEGIN;

-- part 1 - delete element from List<LimitReductionEntity> limitReductions;
DELETE
FROM limit_reduction_entity_reductions
WHERE index >= 5;


-- part 2 - add element into LimitReductionEntity
UPDATE limit_reduction_entity_reductions
SET reductions = 1.0
WHERE index < 6;

-- Insert missing values up to 6 elements
INSERT INTO limit_reduction_entity_reductions (limit_reduction_entity_id, index, reductions)
SELECT
    lre.id,
    numbers.index,
    1.0
FROM limit_reduction_entity lre
         CROSS JOIN (
    SELECT 0 as index UNION ALL
    SELECT 1 UNION ALL
    SELECT 2 UNION ALL
    SELECT 3 UNION ALL
    SELECT 4 UNION ALL
    SELECT 5
) numbers
WHERE NOT EXISTS (
    SELECT 1
    FROM limit_reduction_entity_reductions lr
    WHERE lr.limit_reduction_entity_id = lre.id
      AND lr.index = numbers.index
);

-- ROLLBACK;