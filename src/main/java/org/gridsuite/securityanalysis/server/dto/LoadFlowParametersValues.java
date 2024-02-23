/**
 Copyright (c) 2024, RTE (http://www.rte-france.com)
 This Source Code Form is subject to the terms of the Mozilla Public
 License, v. 2.0. If a copy of the MPL was not distributed with this
 file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.loadflow.LoadFlowParameters;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Map;

/**
 * @author Abdelsalem Hedhili <abdelsalem.hedhili@rte-france.com>
 */
@Getter
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoadFlowParametersValues {

    LoadFlowParameters commonParameters;

    Map<String, String> specificParameters;
}
