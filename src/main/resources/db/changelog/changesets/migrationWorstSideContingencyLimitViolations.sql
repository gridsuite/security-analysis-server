-- check rules applied in org/gridsuite/securityanalysis/server/util/ContingencyLimitViolationWorstSideUtils.java, this migration follow WORSE_SIDE_COMPARATOR and computeWorstSideBySubjectId rules
WITH ranked AS (
    SELECT
        id,
        ROW_NUMBER() OVER (
            PARTITION BY subject_limit_violation_id, contingency_uuid
            ORDER BY
                acceptable_duration ASC NULLS LAST,
                upcoming_acceptable_duration ASC NULLS LAST,
                loading DESC NULLS LAST,
                CASE side
                    WHEN 'ONE' THEN 1
                    WHEN 'TWO' THEN 2
                    WHEN 'THREE' THEN 3
                    ELSE NULL
                END ASC NULLS LAST
        ) AS rn
    FROM contingency_limit_violation
)
UPDATE contingency_limit_violation clv
SET is_worst_side = (ranked.rn = 1)
FROM ranked
WHERE clv.id = ranked.id;