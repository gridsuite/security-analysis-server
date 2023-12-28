package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.Branch;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;

import java.util.ArrayList;
import java.util.List;

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

    public static LimitViolationDTO toDto(AbstractLimitViolationEntity limitViolation) {
        return LimitViolationDTO.builder()
            .limitType(limitViolation.getLimitType())
            .limitName(limitViolation.getLimitName())
            .side(limitViolation.getSide())
            .acceptableDuration((int) limitViolation.getAcceptableDuration())
            .limit(limitViolation.getLimit())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .loading(limitViolation.getLoading())
            .build();
    }

    public List<String> toCsvRow() {
        List<String> csvRow = new ArrayList<>();
        csvRow.add(this.getLimitType() != null ? this.getLimitType().name() : "");
        csvRow.add(replaceNullWithEmptyString(this.getLimitName()));
        csvRow.add(Double.toString(this.getLimit()));
        csvRow.add(Double.toString(this.getValue()));
        csvRow.add(replaceNullWithEmptyString(this.getLoading()));
        csvRow.add(Integer.toString(this.getAcceptableDuration()));
        csvRow.add(this.getSide() != null ? this.getSide().name() : "");
        return csvRow;
    }

    public static String replaceNullWithEmptyString(Object input) {
        return input == null ? "" : input.toString();
    }

}
