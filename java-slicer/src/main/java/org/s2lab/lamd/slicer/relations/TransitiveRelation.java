/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer.relations;

/***
 * Represents a transitive relation where the parameter indirectly affects the api call
 * through intermediate steps or methods.
 */
public class TransitiveRelation extends Relation {
  public TransitiveRelation(String source) {
    super(source);
  }

  @Override
  public String getType() {
    return "Transitive";
  }

  @Override
  public String toFormattedString() {
    return "[Transitive] " + source;
  }
}
