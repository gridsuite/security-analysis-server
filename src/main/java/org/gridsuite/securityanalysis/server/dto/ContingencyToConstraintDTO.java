package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyToConstraintDTO {
    public String id;
    public String status;
    public List<ContingencyElementDTO> elements;
    public List<ConstraintFromContingencyDTO> constraints;
}
