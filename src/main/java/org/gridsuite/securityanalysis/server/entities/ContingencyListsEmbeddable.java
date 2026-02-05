/**
 * Copyright (c) 2025, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.dto.ContingencyListsDTO;

import java.util.UUID;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Embeddable
public class ContingencyListsEmbeddable {
    private UUID id;
    private String name;
    private boolean activated;

    public ContingencyListsEmbeddable(ContingencyListsDTO contingencyListsDTO) {
        this.id = contingencyListsDTO.getId();
        this.name = contingencyListsDTO.getName();
        this.activated = contingencyListsDTO.isActivated();
    }
}
