/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import org.springframework.data.cassandra.core.cql.PrimaryKeyType;
import org.springframework.data.cassandra.core.mapping.Column;
import org.springframework.data.cassandra.core.mapping.PrimaryKeyColumn;
import org.springframework.data.cassandra.core.mapping.Table;

import java.io.Serializable;
import java.util.List;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Getter
@Setter
@AllArgsConstructor
@Table("contingency")
public class ContingencyEntity implements Serializable {

    @PrimaryKeyColumn(name = "resultUuid", type = PrimaryKeyType.PARTITIONED)
    private UUID resultUuid;

    @PrimaryKeyColumn(name = "contingencyId", type = PrimaryKeyType.CLUSTERED)
    private String contingencyId;

    @Column("branchIds")
    private List<String> branchIds;

    @Column("generatorIds")
    private List<String> generatorIds;
}
