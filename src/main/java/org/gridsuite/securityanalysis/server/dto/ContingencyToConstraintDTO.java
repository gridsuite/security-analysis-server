package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyToConstraintDTO {
    private String id;
    private String status;
    private List<ContingencyElementDTO> elements;
    private List<ConstraintFromContingencyDTO> constraints;
}
