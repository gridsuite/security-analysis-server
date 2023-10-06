package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.List;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyToConstraintDTO {
    String id;
    String status;
    List<ConstraintFromContingencyDTO> constraint;
}
