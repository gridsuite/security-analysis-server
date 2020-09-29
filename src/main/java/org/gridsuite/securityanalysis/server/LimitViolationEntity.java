/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.cassandra.core.cql.PrimaryKeyType;
import org.springframework.data.cassandra.core.mapping.Column;
import org.springframework.data.cassandra.core.mapping.PrimaryKeyColumn;
import org.springframework.data.cassandra.core.mapping.Table;

import java.io.Serializable;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Getter
@Setter
@AllArgsConstructor
@Table("limitViolation")
public class LimitViolationEntity implements Serializable {

    @PrimaryKeyColumn(name = "resultUuid", ordinal = 0, type = PrimaryKeyType.PARTITIONED)
    private UUID resultUuid;

    @PrimaryKeyColumn(name = "limitType", ordinal = 1, type = PrimaryKeyType.CLUSTERED)
    private LimitViolationType limitType;

    @PrimaryKeyColumn(name = "contingencyId", ordinal = 2, type = PrimaryKeyType.CLUSTERED)
    private String contingencyId;

    @PrimaryKeyColumn(name = "subjectId", ordinal = 3, type = PrimaryKeyType.CLUSTERED)
    private String subjectId;

    @Column("subjectName")
    private String subjectName;

    @Column("limit_")
    private double limit;

    @Column("limitName")
    private String limitName;

    @Column("acceptableDuration")
    private int acceptableDuration;

    @Column("limitReduction")
    private float limitReduction;

    @Column("value")
    private double value;

    @Column("side")
    private Branch.Side side;
}
