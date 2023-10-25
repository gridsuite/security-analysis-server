/**
* Copyright (c) 2023, RTE (http://www.rte-france.com)
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package org.gridsuite.securityanalysis.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.List;

/**
 * An object that can be used to filter data with the JPA Criteria API (via Spring Specification)
 * @param dataType the type of data we want to filter (text, number)
 * @param type the type of filter (contains, startsWith...)
 * @param value the value of the filter
 * @param column the column / field on which the filter will be applied
 */
public record FilterDTO(DataType dataType, Type type, Object value, FilterColumn column) {

    public enum DataType {
        @JsonProperty("text")
        TEXT,
    }

    public enum Type {
        @JsonProperty("contains")
        CONTAINS,
        @JsonProperty("startsWith")
        STARTS_WITH,
    }

    public enum FilterColumn {
        @JsonProperty("contingencyId")
        CONTINGENCY_ID,
        @JsonProperty("status")
        STATUS,
        @JsonProperty("subjectId")
        SUBJECT_ID,
        @JsonProperty("limitType")
        LIMIT_TYPE,
        @JsonProperty("limitName")
        LIMIT_NAME,
        @JsonProperty("side")
        SIDE
    }

    public static List<FilterDTO> fromStringToList(String filters) throws JsonProcessingException {
        if (filters == null || filters.isEmpty()) {
            return List.of();
        }
        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.readValue(filters, new TypeReference<>() {
        });
    }
}