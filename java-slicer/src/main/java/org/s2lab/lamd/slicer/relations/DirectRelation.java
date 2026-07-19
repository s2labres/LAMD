/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer.relations;

/***
 * Represents a direct relation where the parameter directly triggers the api call.
 */
public class DirectRelation extends Relation {
  public DirectRelation(String source) {
    super(source);
  }

  @Override
  public String getType() {
    return "Direct";
  }

  @Override
  public String toFormattedString() {
    return "[Direct] " + source;
  }
}
