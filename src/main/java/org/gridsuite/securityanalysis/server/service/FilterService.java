/**
 * Copyright (c) 2024, RTE (http://www.rte-france.com)
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.service;

import com.powsybl.network.store.client.NetworkStoreService;
import lombok.NonNull;
import org.gridsuite.computation.dto.GlobalFilter;
import org.gridsuite.computation.dto.ResourceFilterDTO;
import org.gridsuite.computation.service.AbstractFilterService;
import org.gridsuite.filter.utils.EquipmentType;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class FilterService extends AbstractFilterService {

    public FilterService(
            NetworkStoreService networkStoreService,
            @Value("${gridsuite.services.filter-server.base-uri:http://filter-server/}") String filterServerBaseUri) {
        super(networkStoreService, filterServerBaseUri);
    }

    public Optional<ResourceFilterDTO> getResourceFilterN(@NonNull UUID networkUuid, @NonNull String variantId, @NonNull GlobalFilter globalFilter) {
        return super.getResourceFilter(networkUuid, variantId, globalFilter, List.of(EquipmentType.VOLTAGE_LEVEL), "subjectLimitViolation.subjectId");
    }

    public Optional<ResourceFilterDTO> getResourceFilterContingencies(@NonNull UUID networkUuid, @NonNull String variantId, @NonNull GlobalFilter globalFilter) {
        return super.getResourceFilter(networkUuid, variantId, globalFilter, List.of(EquipmentType.LINE), ContingencyEntity.Fields.contingencyId);
    }

    public Optional<ResourceFilterDTO> getResourceFilterSubjectLimitViolations(@NonNull UUID networkUuid, @NonNull String variantId, @NonNull GlobalFilter globalFilter) {
        return super.getResourceFilter(networkUuid, variantId, globalFilter, List.of(EquipmentType.VOLTAGE_LEVEL), SubjectLimitViolationEntity.Fields.subjectId);
    }
}
