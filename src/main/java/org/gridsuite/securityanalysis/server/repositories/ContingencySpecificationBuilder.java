package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ContingencySpecificationBuilder extends AbstractCommonSpecificationBuilder<ContingencyEntity> {
    public ContingencySpecificationBuilder() {
    }

    public boolean isParentFilter(ResourceFilterDTO filter) {
        return List.of(ResourceFilterDTO.Column.CONTINGENCY_ID, ResourceFilterDTO.Column.STATUS).contains(filter.column());
    }
}
