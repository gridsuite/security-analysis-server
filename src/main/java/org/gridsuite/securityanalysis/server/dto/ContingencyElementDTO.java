package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.contingency.ContingencyElementType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyElementEmbeddable;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyElementDTO {
    private String id;
    private ContingencyElementType elementType;

    public static ContingencyElementDTO toDto(ContingencyElementEmbeddable contingencyElement) {
        return new ContingencyElementDTO(contingencyElement.getElementId(), contingencyElement.getElementType());
    }
}
