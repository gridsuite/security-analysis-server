package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.security.SecurityAnalysisParameters;
import lombok.Builder;

import java.util.List;

@Builder
public record SecurityAnalysisParametersWrapper(
        SecurityAnalysisParameters securityAnalysisParameters,
        List<List<Double>> limitReductions
) { }
