/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import java.util.Collection;

import org.apache.commons.lang3.builder.ReflectionToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 * @author Laurent Garnier <laurent.garnier at rte-france.com>
 */
public class MatcherJson<T> extends TypeSafeMatcher<T> {

    private static class RecursiveJsonToStringStyle extends ToStringStyle {

        private static final int INFINITE_DEPTH = -1;

        /**
         * Setting this field to 0 will have the same effect as using original {@link #ToStringStyle}: it will print all 1st
         * level values without traversing into them. Setting to 1 will traverse up to 2nd level and so on.
         */
        private final int maxDepth;

        private int depth;

        public RecursiveJsonToStringStyle() {
            this(INFINITE_DEPTH);

            setNullText("");
        }

        public RecursiveJsonToStringStyle(int maxDepth) {
            setUseShortClassName(true);
            setUseIdentityHashCode(false);

            this.maxDepth = maxDepth;
        }

        @Override
        public void appendStart(StringBuffer buffer, Object object) {
            if (object != null) {
                this.appendContentStart(buffer);
                this.appendFieldSeparator(buffer);
            }
        }

        @Override
        protected void appendFieldStart(StringBuffer buffer, String fieldName) {
            if (fieldName != null) {
                buffer.append(fieldName);
                buffer.append(":");
            }
        }

        @Override
        protected void appendDetail(StringBuffer buffer, String fieldName, Object value) {
            if (value.getClass().getName().startsWith("java.lang.")
                || maxDepth != INFINITE_DEPTH && depth >= maxDepth) {
                buffer.append(value);
            } else {
                depth++;
                buffer.append(ReflectionToStringBuilder.toString(value, this));
                buffer.append(System.lineSeparator());
                depth--;
            }
        }

        @Override
        protected void appendDetail(StringBuffer buffer, String fieldName, Collection<?> coll) {
            depth++;
            buffer.append(ReflectionToStringBuilder.toString(coll.toArray(), this, true, true));
            depth--;
        }
    }

    RecursiveJsonToStringStyle style = new RecursiveJsonToStringStyle();

    ObjectMapper mapper;

    T reference;

    public MatcherJson(ObjectMapper mapper, T val) {
        this.mapper = mapper;
        this.reference = val;
    }

    @SneakyThrows
    @Override
    public boolean matchesSafely(T s) {
        return mapper.writeValueAsString(reference).equals(mapper.writeValueAsString(s));
    }

    @Override
    public void describeTo(Description description) {
        description.appendText(ReflectionToStringBuilder.toString(reference, style));
    }

    protected void describeMismatchSafely(T item, Description mismatchDescription) {
        String toAdd = ReflectionToStringBuilder.toString(item, style);
        mismatchDescription.appendText("was ").appendText(toAdd);
    }

}
