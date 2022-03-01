/*
  Copyright (c) 2021, RTE (http://www.rte-france.com)
  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */
package org.gridsuite.securityanalysis.server.util;

import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;

/**
 * @author Slimane Amar <slimane.amar at rte-france.com>
 * @author Laurent Garnier <laurent.garnier at rte-france.com>
 */
public class MatcherJson<T> extends TypeSafeMatcher<T> {

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

    @SneakyThrows
    @Override
    public void describeTo(Description description) {
        description.appendText(mapper.writeValueAsString(reference));
    }

    @SneakyThrows
    protected void describeMismatchSafely(T item, Description mismatchDescription) {
        mismatchDescription.appendText("was ").appendText(mapper.writeValueAsString(item));
    }

}
