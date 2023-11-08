/**
* Copyright (c) 2023, RTE (http://www.rte-france.com)
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

package org.gridsuite.securityanalysis.server.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * @author Kevin Le Saulnier <kevin.lesaulnier at rte-france.com>
 */

/**
 * An object that can be used to filter data with the JPA Criteria API (via Spring Specification)
 * @param dataType the type of data we want to filter (text, number)
 * @param type the type of filter (contains, startsWith...)
 * @param value the value of the filter
 * @param column the column / field on which the filter will be applied
 */
public record ResourceFilterDTO(DataType dataType, Type type, Object value, Column column) {

    public enum DataType {
        @JsonProperty("text")
        TEXT,

        @JsonProperty("number")
        NUMBER,
    }

    public enum Type {
        CONTAINS,
        @JsonProperty("startsWith")
        STARTS_WITH,
        EQUALS,

        @JsonProperty("notEqual")
        NOT_EQUAL,
        @JsonProperty("lessThanOrEqual")
        LESS_THAN_OR_EQUAL,
        @JsonProperty("greaterThanOrEqual")
        GREATER_THAN_OR_EQUAL
    }

    public enum Column {
        @JsonProperty("contingencyId")
        CONTINGENCY_ID("contingencyId"),
        STATUS("status"),
        @JsonProperty("subjectId")
        SUBJECT_ID("subjectId"),
        @JsonProperty("limitType")
        LIMIT_TYPE("limitType"),
        @JsonProperty("limitName")
        LIMIT_NAME("limitName"),
        @JsonProperty("limit")
        LIMIT("limit"),
        @JsonProperty("value")
        VALUE("value"),
        @JsonProperty("side")
        SIDE("side"),
        @JsonProperty("loading")
        LOADING("loading");

        private final String columnName;

        Column(String columnName) {
            this.columnName = columnName;
        }

        public String columnName() {
            return columnName;
        }
    }
}
