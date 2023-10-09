package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.ContingencyLimitViolationEntity;

@Getter
@AllArgsConstructor
@NoArgsConstructor
public class ConstraintFromContingencyDTO {
    private String subjectId;
    private LimitViolationType limitType;
    private String limitName;
    private Branch.Side side;
    private int acceptableDuration;
    private double limit;
    private double value;

    public static ConstraintFromContingencyDTO toDto(ContingencyLimitViolationEntity limitViolation) {
        String subjectId = limitViolation.getConstraint() != null
            ? limitViolation.getConstraint().getSubjectId()
            : null;
        return new ConstraintFromContingencyDTO(subjectId, limitViolation.getLimitType(), limitViolation.getLimitName(), limitViolation.getSide(), limitViolation.getAcceptableDuration(), limitViolation.getLimit(), limitViolation.getValue());
    }
}
