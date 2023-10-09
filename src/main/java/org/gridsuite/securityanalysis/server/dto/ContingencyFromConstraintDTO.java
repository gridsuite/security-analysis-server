package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyEntity;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;

import java.util.List;
import java.util.stream.Collectors;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyFromConstraintDTO {
    private String contingencyId;
    private String computationStatus;
    private LimitViolationType limitType;
    private String limitName;
    private Branch.Side side;
    private int acceptableDuration;
    private double limit;
    private double value;
    private List<ContingencyElementDTO> elements;

    public static ContingencyFromConstraintDTO toDto(ContingencyLimitViolationEntity limitViolation) {
        ContingencyEntity contingency = limitViolation.getContingency();
        return new ContingencyFromConstraintDTO(
            contingency.getContingencyId(),
            contingency.getStatus(),
            limitViolation.getLimitType(),
            limitViolation.getLimitName(),
            limitViolation.getSide(),
            limitViolation.getAcceptableDuration(),
            limitViolation.getLimit(),
            limitViolation.getValue(),
            contingency.getContingencyElements().stream().map(ContingencyElementDTO::toDto).collect(Collectors.toList())
        );
    }
}
