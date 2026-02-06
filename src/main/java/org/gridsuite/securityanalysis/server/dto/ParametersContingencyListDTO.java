/**
 * Copyright (c) 2025, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;
import lombok.*;

import java.util.List;

/**
 * @author Caroline Jeandat {@literal <caroline.jeandat at rte-france.com>}
 */
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class ParametersContingencyListDTO {
    List<ParametersContingenciesDTO> contingencies;
    String description;
    boolean activated;
}
