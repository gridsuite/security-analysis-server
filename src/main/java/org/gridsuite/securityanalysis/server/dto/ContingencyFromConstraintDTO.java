package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ContingencyFromConstraintDTO {
    public String contingencyId;
    public String computationStatus;
    public LimitViolationType limitType;
    public String limitName;
    public Branch.Side side;
    public int acceptableDuration;
    public double limit;
    public double value;
}
