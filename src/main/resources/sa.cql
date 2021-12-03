CREATE TABLE computationStatus (
    resultUuid uuid,
    contingencyId text,
    ok boolean,
    PRIMARY KEY (resultUuid, contingencyId)
);

CREATE TABLE limitViolation (
    resultUuid uuid,
    limitType text,
    contingencyId text,
    subjectId text,
    subjectName text,
    limit_ double,
    limitName text,
    acceptableDuration int,
    limitReduction float,
    value double,
    side text,
    PRIMARY KEY (resultUuid, limitType, contingencyId, subjectId)
);

CREATE TABLE contingency (
    resultUuid uuid,
    contingencyId text,
    branchIds list<text>,
    generatorIds list<text>,
    PRIMARY KEY (resultUuid, contingencyId)
);

CREATE TABLE globalStatus (
    resultUuid uuid,
    status text,
    PRIMARY KEY (resultUuid)
);

