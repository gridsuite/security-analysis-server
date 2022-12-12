/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.entities;

import java.util.UUID;

import java.io.Serializable;

import javax.persistence.*;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.dto.SecurityAnalysisStatus;

/**
 * @author Franck Lecuyer <franck.lecuyer at rte-france.com>
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "globalStatus")
public class GlobalStatusEntity implements Serializable {

    @Id
    private UUID resultUuid;

    @Enumerated(EnumType.STRING)
    private SecurityAnalysisStatus status;
}
