/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import java.util.Objects;

public class GraphEdge<T> {

  private final T src;
  private final T tgt;

  public GraphEdge(T src, T tgt) {
    this.src = src;
    this.tgt = tgt;
  }

  public T getSrc() {
    return src;
  }

  public T getTgt() {
    return tgt;
  }

  @Override
  public String toString() {
    return src.toString() + " -> " + tgt.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    GraphEdge<?> other = (GraphEdge<?>) obj;
    return src.equals(other.src) && tgt.equals(other.tgt);
  }

  @Override
  public int hashCode() {
    return Objects.hash(src, tgt);
  }
}
