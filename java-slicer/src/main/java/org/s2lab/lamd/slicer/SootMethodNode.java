/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import soot.SootMethod;

public class SootMethodNode {
  private final SootMethod sootMethod;

  public SootMethodNode(SootMethod sootMethod) {
    this.sootMethod = sootMethod;
  }

  public SootMethod getSootMethod() {
    return sootMethod;
  }

  @Override
  public String toString() {
    return sootMethod.getSignature();
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null || getClass() != obj.getClass()) {
      return false;
    }
    SootMethodNode other = (SootMethodNode) obj;
    return sootMethod.toString().equals(other.sootMethod.toString());
  }

  @Override
  public int hashCode() {
    return sootMethod.toString().hashCode();
  }
}
