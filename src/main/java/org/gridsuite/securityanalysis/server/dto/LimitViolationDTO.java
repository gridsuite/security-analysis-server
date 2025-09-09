package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.iidm.network.ThreeSides;
import com.powsybl.security.LimitViolationType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.gridsuite.securityanalysis.server.entities.AbstractLimitViolationEntity;
import org.gridsuite.securityanalysis.server.util.CsvExportUtils;

import java.text.NumberFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@AllArgsConstructor
@NoArgsConstructor
@Builder
@Getter
public class LimitViolationDTO {
    private LimitViolationType limitType;
    private String limitName;
    private String nextLimitName;
    private ThreeSides side;
    private Integer acceptableDuration;
    private Integer upcomingAcceptableDuration;
    private double limit;
    private Double patlLimit;
    private double limitReduction;
    private double value;
    private Double loading;
    private Double patlLoading;
    private String locationId;

    public static LimitViolationDTO toDto(AbstractLimitViolationEntity limitViolation) {
        return LimitViolationDTO.builder()
            .limitType(limitViolation.getLimitType())
            .limitName(limitViolation.getLimitName())
            .nextLimitName(limitViolation.getNextLimitName())
            .side(limitViolation.getSide())
            .acceptableDuration(limitViolation.getAcceptableDuration())
            .upcomingAcceptableDuration(limitViolation.getUpcomingAcceptableDuration())
            .limit(limitViolation.getLimit())
            .patlLimit(limitViolation.getPatlLimit())
            .limitReduction(limitViolation.getLimitReduction())
            .value(limitViolation.getValue())
            .loading(limitViolation.getLoading())
            .patlLoading(limitViolation.getPatlLoading())
            .locationId(limitViolation.getLocationId())
            .build();
    }

    private static String convertDoubleToLocale(Double value, String language) {
        NumberFormat nf = NumberFormat.getInstance(language != null && language.equals("fr") ? Locale.FRENCH : Locale.US);
        nf.setGroupingUsed(false);
        return nf.format(value);
    }

    public List<String> toCsvRow(Map<String, String> translations, String language) {
        List<String> csvRow = new ArrayList<>();
        csvRow.add(this.getLocationId());
        csvRow.add(this.getLimitType() != null ? CsvExportUtils.translate(this.getLimitType().name(), translations) : "");
        csvRow.add(CsvExportUtils.replaceNullWithEmptyString(CsvExportUtils.translate(this.getLimitName(), translations)));
        csvRow.add(convertDoubleToLocale(this.getLimit(), language));
        csvRow.add(convertDoubleToLocale(this.getValue(), language));
        csvRow.add(this.getLoading() == null ? "" : convertDoubleToLocale(this.getLoading(), language));
        csvRow.add(this.getAcceptableDuration() == Integer.MAX_VALUE ? null : Integer.toString(this.getAcceptableDuration()));
        csvRow.add(this.getSide() != null ? CsvExportUtils.translate(this.getSide().name(), translations) : "");
        return csvRow;
    }
}
