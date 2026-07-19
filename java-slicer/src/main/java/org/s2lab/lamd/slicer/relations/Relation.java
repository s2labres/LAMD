/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer.relations;

import java.util.Objects;

public abstract class Relation {
  protected String source;
  protected String target;

  public Relation(String source) {
    this.source = source;
  }

  public Relation(String source, String target) {
    this.source = source;
    this.target = target;
  }

  public abstract String getType();

  public abstract String toFormattedString();

  @Override
  public String toString() {
    return getType() + ": " + source + " -> " + target;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null || getClass() != obj.getClass()) return false;
    Relation relation = (Relation) obj;
    return Objects.equals(source, relation.source)
        && Objects.equals(target, relation.target)
        && Objects.equals(getType(), relation.getType());
  }

  @Override
  public int hashCode() {
    return Objects.hash(source, target, getType());
  }
}
