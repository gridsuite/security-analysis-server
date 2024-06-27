package org.gridsuite.securityanalysis.server.util;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Setter
@Getter
@Configuration
@ConfigurationProperties(prefix = "default-limit-reductions")
public class LimitReductionConfig {

    private List<VoltageLevel> voltageLevels;
    private List<LimitDuration> limitDurations;
    private List<List<Double>> defaultValues;

    @Setter
    @Getter
    public static class LimitDuration {
        private Integer lowBound;
        private boolean lowClosed;
        private Integer highBound;
        private boolean highClosed;
    }

    @Setter
    @Getter
    public static class VoltageLevel {
        private double nominalV;
        private double lowBound;
        private double highBound;
    }
}
