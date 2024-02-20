package org.gridsuite.securityanalysis.server.repositories;

import org.gridsuite.securityanalysis.server.dto.ResourceFilterDTO;
import org.gridsuite.securityanalysis.server.entities.SubjectLimitViolationEntity;
import org.springframework.stereotype.Service;

@Service
public class SubjectLimitViolationSpecificationBuilder extends AbstractCommonSpecificationBuilder<SubjectLimitViolationEntity> {
    public SubjectLimitViolationSpecificationBuilder() {
    }

    public boolean isParentFilter(ResourceFilterDTO filter) {
        return filter.column().equals(ResourceFilterDTO.Column.SUBJECT_ID);
    }
}
