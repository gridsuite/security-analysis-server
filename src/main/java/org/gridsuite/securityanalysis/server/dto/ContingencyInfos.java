package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.contingency.Contingency;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Set;

@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ContingencyInfos {
    private Contingency contingency;
    Set<String> notFoundElements;

    public ContingencyInfos(Contingency contingency) {
        this(contingency, Set.of());
    }
}
