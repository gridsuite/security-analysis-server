package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.contingency.Contingency;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.Map;
import java.util.Set;

@Setter
@Getter
@NoArgsConstructor
@AllArgsConstructor
public class ContingencyInfos {
    Contingency contingency;
    Map<String, Set<String>> notFoundElements;

    public ContingencyInfos(Contingency contingency) {
        this(contingency, Map.of());
    }
}

