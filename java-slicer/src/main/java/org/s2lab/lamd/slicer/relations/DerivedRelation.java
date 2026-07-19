/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer.relations;

/** Represents a value derived from another relevant value. */
public class DerivedRelation extends Relation {
  public DerivedRelation(String source, String target) {
    super(source, target);
  }

  @Override
  public String getType() {
    return "Derived";
  }

  @Override
  public String toFormattedString() {
    return "[Derived] " + source + " <- " + target;
  }
}
