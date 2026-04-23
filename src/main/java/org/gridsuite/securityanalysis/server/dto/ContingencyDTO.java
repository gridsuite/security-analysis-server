package org.gridsuite.securityanalysis.server.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;

import java.util.List;
import java.util.stream.Collectors;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Builder
public class ContingencyDTO {
    private String contingencyId;
    private String status;
    private List<ContingencyElementDTO> elements;

    public static ContingencyDTO toDto(ContingencyEntity contingency) {
        return ContingencyDTO.builder()
            .contingencyId(contingency.getContingencyId())
            .status(contingency.getStatus())
            .elements(contingency.getContingencyElements().stream().map(ContingencyElementDTO::toDto).collect(Collectors.toList()))
            .build();
    }
}
