/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import java.util.UUID;

import java.io.Serializable;

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
@IdClass(ComputationStatusEntity.ID.class)
@Table(name = "computationStatus")
public class ComputationStatusEntity implements Serializable {

    @NoArgsConstructor
    @Getter
    @Embeddable
    static class ID implements Serializable {
        private UUID resultUuid;

        private String contingencyId;
    }

    @Id
    private UUID resultUuid;

    @Id
    private String contingencyId;

    private boolean ok;
}
