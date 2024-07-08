package org.gridsuite.securityanalysis.server.dto;

import com.powsybl.security.SecurityAnalysisParameters;

import java.util.List;

public record SecurityAnalysisParametersWrapper(
        SecurityAnalysisParameters parameters,
        List<List<Double>> limitReductions,
        List<String> contingencyListNames
) { }
