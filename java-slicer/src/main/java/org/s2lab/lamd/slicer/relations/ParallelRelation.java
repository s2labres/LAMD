/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer.relations;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/** Represents an unordered group of two or more variables that work together. */
public class ParallelRelation extends Relation {
  private final List<String> variables;

  public ParallelRelation(String source, String target) {
    this(java.util.Arrays.asList(source, target));
  }

  public ParallelRelation(Collection<String> variables) {
    super(firstVariable(variables));
    List<String> canonicalVariables = new ArrayList<>(new TreeSet<>(variables));
    if (canonicalVariables.size() < 2) {
      throw new IllegalArgumentException(
          "Parallel relations require at least two distinct variables");
    }
    this.variables = Collections.unmodifiableList(canonicalVariables);
  }

  private static String firstVariable(Collection<String> variables) {
    if (variables == null || variables.isEmpty()) {
      throw new IllegalArgumentException("Parallel relations require at least two variables");
    }
    return variables.iterator().next();
  }

  @Override
  public String getType() {
    return "Parallel";
  }

  @Override
  public String toFormattedString() {
    return "[Parallel] " + String.join(" and ", variables) + " work together";
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (!(obj instanceof ParallelRelation)) return false;
    ParallelRelation relation = (ParallelRelation) obj;
    return variables.equals(relation.variables);
  }

  @Override
  public int hashCode() {
    return Objects.hash(getType(), variables);
  }
}
