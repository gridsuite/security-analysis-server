/*
 * Copyright (c) 2022, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;

import com.powsybl.contingency.ContingencyElementType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * @author Laurent GARNIER <laurent.garnier at rte-france.com>
 */
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Embeddable
public class ContingencyElementEmbeddable {

    @Column
    private ContingencyElementType elementType;

    @Column
    private String elementId;
}
