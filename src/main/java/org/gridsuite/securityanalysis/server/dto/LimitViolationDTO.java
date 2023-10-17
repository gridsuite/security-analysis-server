package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
public class LimitViolationDTO {
    private LimitViolationType limitType;
    private String limitName;
    private Branch.Side side;
    private int acceptableDuration;
    private double limit;
    private double limitReduction;
    private double value;
    private Double loading;

    public static LimitViolationDTO toDto (AbstractLimitViolationEntity limitViolation) {
        Double computedLoading = LimitViolationType.CURRENT.equals(limitViolation.getLimitType())
            ? (100 * limitViolation.getValue()) / (limitViolation.getLimit() * limitViolation.getLimitReduction())
            : null;

        return LimitViolationDTO.builder()
            .limitType(limitViolation.getLimitType())
            .limitName(limitViolation.getLimitName())
            .side(limitViolation.getSide())
            .acceptableDuration(limitViolation.getAcceptableDuration())
            .limit(limitViolation.getLimit())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .loading(computedLoading)
            .build();
    }
}
