/**
 * Copyright (c) 2025, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import lombok.*;
import org.gridsuite.securityanalysis.server.entities.ContingencyListsEmbeddable;

import java.util.UUID;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@Data
@Builder
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ContingencyListsDTO {
    private UUID id;
    private String name;
    private boolean activated;

    public ContingencyListsDTO(ContingencyListsEmbeddable contingencyListsEmbeddable) {
        this.id = contingencyListsEmbeddable.getId();
        this.name = contingencyListsEmbeddable.getName();
        this.activated = contingencyListsEmbeddable.isActivated();
    }

    public ContingencyListsEmbeddable toEmbeddable() {
        return new ContingencyListsEmbeddable(this);
    }
}
