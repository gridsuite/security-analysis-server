package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.contingency.ContingencyElementType;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyElementEmbeddable;

@AllArgsConstructor
@NoArgsConstructor
public class ContingencyElementDTO {
    public String id;
    public ContingencyElementType elementType;

    public static ContingencyElementDTO toDto (ContingencyElementEmbeddable contingencyElement) {
        return new ContingencyElementDTO(contingencyElement.getElementId(), contingencyElement.getElementType());
    }
}
