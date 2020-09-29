CREATE TABLE sa.computationStatus (
    resultUuid uuid,
    contingencyId text,
    ok boolean,
    PRIMARY KEY (resultUuid, contingencyId)
);

CREATE TABLE sa.limitViolation (
    resultUuid uuid,
    contingencyId text,
    subjectId text,
    limitType text,
    subjectName text,
    limit_ double,
    limitName text,
    acceptableDuration int,
    limitReduction float,
    value double,
    side text,
    PRIMARY KEY (resultUuid, contingencyId, subjectId, limitType)
);

CREATE TABLE sa.contingency (
    resultUuid uuid,
    contingencyId text,
    branchIds list<text>,
    generatorIds list<text>,
    PRIMARY KEY (resultUuid, contingencyId)
);
