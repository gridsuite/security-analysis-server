package org.gridsuite.securityanalysis.server.dto;

import lombok.*;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class CsvTranslationDTO {
    List<String> headers;

    Map<String, String> enumValueTranslations;
}
