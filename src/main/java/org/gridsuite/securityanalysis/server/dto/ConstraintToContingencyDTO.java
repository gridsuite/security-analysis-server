package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ConstraintToContingencyDTO {
    private String constraintId;

    private List<ContingencyFromConstraintDTO> contingencies;
}
