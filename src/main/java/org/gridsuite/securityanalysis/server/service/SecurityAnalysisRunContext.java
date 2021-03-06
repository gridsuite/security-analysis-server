/**
 * Copyright (c) 2020, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.security.SecurityAnalysisParameters;

import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * @author Geoffroy Jamgotchian <geoffroy.jamgotchian at rte-france.com>
 */
public class SecurityAnalysisRunContext {

    private final UUID networkUuid;

    private final List<UUID> otherNetworkUuids;

    private final List<String> contingencyListNames;

    private final String receiver;

    private final SecurityAnalysisParameters parameters;

    public SecurityAnalysisRunContext(UUID networkUuid, List<UUID> otherNetworkUuids, List<String> contingencyListNames,
                                      String receiver, SecurityAnalysisParameters parameters) {
        this.networkUuid = Objects.requireNonNull(networkUuid);
        this.otherNetworkUuids = Objects.requireNonNull(otherNetworkUuids);
        this.contingencyListNames = Objects.requireNonNull(contingencyListNames);
        this.receiver = receiver;
        this.parameters = Objects.requireNonNull(parameters);
    }

    public UUID getNetworkUuid() {
        return networkUuid;
    }

    public List<UUID> getOtherNetworkUuids() {
        return otherNetworkUuids;
    }

    public List<String> getContingencyListNames() {
        return contingencyListNames;
    }

    public String getReceiver() {
        return receiver;
    }

    public SecurityAnalysisParameters getParameters() {
        return parameters;
    }
}
