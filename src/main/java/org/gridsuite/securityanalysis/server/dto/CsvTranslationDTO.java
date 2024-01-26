package org.gridsuite.securityanalysis.server.dto;

import lombok.*;

import java.util.List;
import java.util.Map;

@Builder
public record CsvTranslationDTO(
    List<String> headers,
    Map<String, String> enumValueTranslations
) { }
