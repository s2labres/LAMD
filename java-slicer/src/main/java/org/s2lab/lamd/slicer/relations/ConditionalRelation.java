/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer.relations;

/***
 * Represents a conditional where the parameter is used to determine if the api call is made.
 */
public class ConditionalRelation extends Relation {
  public ConditionalRelation(String source) {
    super(source);
  }

  @Override
  public String getType() {
    return "Conditional";
  }

  @Override
  public String toFormattedString() {
    return "[Conditional] " + source;
  }
}
