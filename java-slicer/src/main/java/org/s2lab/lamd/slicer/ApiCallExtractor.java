/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import java.io.IOException;
import java.util.*;
import org.graphstream.stream.GraphParseException;
import soot.*;
import soot.jimple.toolkits.callgraph.CallGraph;

public class ApiCallExtractor {
  private final SootUtility utility = new SootUtility();
  private final Slicer slicer = new Slicer();

  public int extract_features(
      CallGraph callGraph, String classOfTheCall, String methodInvoked, int featureIndex, int k)
      throws IOException, GraphParseException {
    int count = 0;

    Map<SootMethod, Set<SootMethod>> methodMap =
        utility.findSootMethod(callGraph, methodInvoked, classOfTheCall);
    if (methodMap == null || methodMap.size() != 1) {
      return 0;
    }

    SootMethod sootMethod = methodMap.keySet().iterator().next();
    if (Instrumenter.msdroid) {
      utility.getKHopSubgraph(
          callGraph, sootMethod, k, Instrumenter.output_dir + "/" + featureIndex);
      return 1;
    }
    Set<SootMethod> correspondingMethods = methodMap.get(sootMethod);
    if (!correspondingMethods.isEmpty()) {
      for (SootMethod correspondingMethod : correspondingMethods) {
        if (!correspondingMethod.hasActiveBody()) {
          continue;
        }
        Body b = correspondingMethod.getActiveBody();
        if (b.toString().contains(methodInvoked)) {
          if (slicer.extractMethodSlice(
              callGraph, correspondingMethod, sootMethod, k, count, featureIndex)) {
            count++;
          }
        }
      }
    }

    return count;
  }
}
