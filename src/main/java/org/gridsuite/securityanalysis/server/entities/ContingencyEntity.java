/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import java.util.List;
import java.util.UUID;

import java.io.Serializable;

import javax.persistence.ElementCollection;
import javax.persistence.Embeddable;
import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.IdClass;
import javax.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "contingency")
@IdClass(ContingencyEntity.ID.class)
public class ContingencyEntity implements Serializable {

    @NoArgsConstructor
    @Getter
    @Embeddable
    static class ID implements Serializable {
        @Id
        private UUID resultUuid;

        @Id
        private String contingencyId;
    }

    @Id
    private UUID resultUuid;

    @Id
    private String contingencyId;

    @ElementCollection
    private List<String> branchIds;

    @ElementCollection
    private List<String> generatorIds;

}
