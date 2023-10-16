package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.loadflow.LoadFlowResult;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class ResultsSelectorDTO {
    String contingencyId;
    String status;
    String subjectId;
    LimitViolationType limitType;
    String limitName;
    Branch.Side side;
    Integer acceptableDuration;
    Double limit;
    Double limitReduction;
    Double value;
    Double loading;
}
