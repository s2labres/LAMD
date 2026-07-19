/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import java.io.*;
import java.util.*;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

public class SootUtility {
  public void initFlowDroid(String apkPath) {
    final InfoflowAndroidConfiguration config = new InfoflowAndroidConfiguration();
    config.getAnalysisFileConfig().setTargetAPKFile(apkPath);
    config.getAnalysisFileConfig().setAndroidPlatformDir(Instrumenter.jarsPath);
    config.setCodeEliminationMode(InfoflowConfiguration.CodeEliminationMode.NoCodeElimination);
    config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);
    SetupApplication app = new SetupApplication(config);
    app.constructCallgraph();
  }

  public Map<SootMethod, Set<SootMethod>> findSootMethod(
      CallGraph callGraph, String method, String class_) {
    SootMethod sootMethod = null;
    Set<SootMethod> corresponding_sootMethods = new HashSet<>();
    for (Iterator<Edge> it = callGraph.iterator(); it.hasNext(); ) {
      Edge edge = it.next();
      SootMethod src = edge.getSrc().method();
      SootMethod tgt = edge.getTgt().method();
      if ((tgt.getName().equals(method) && tgt.getDeclaringClass().getName().equals(class_))) {
        if (sootMethod == null) {
          sootMethod = tgt;
        }
        corresponding_sootMethods.add(src);
      }
    }

    if (sootMethod != null) {
      Map<SootMethod, Set<SootMethod>> methodMap = new HashMap<>();
      methodMap.put(sootMethod, corresponding_sootMethods);
      return methodMap;
    }
    return null;
  }

  public List<String> getSensitiveAPIList(String path) {
    List<String> sensitiveAPIList = new ArrayList<>();
    try {
      BufferedReader reader = new BufferedReader(new FileReader(path));
      String line = reader.readLine();
      while (line != null) {
        sensitiveAPIList.add(line);
        line = reader.readLine();
      }
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
    return sensitiveAPIList;
  }

  public void getKHopSubgraph(CallGraph cg, SootMethod methodSearched, int k, String outputDir) {
    Set<SootMethod> subgraphNodes = new HashSet<>();
    subgraphNodes.add(methodSearched);
    Set<SootMethod> visited = new HashSet<>();
    Queue<SootMethod> queue = new LinkedList<>();
    queue.add(methodSearched);
    visited.add(methodSearched);

    while (!queue.isEmpty() && k >= 0) {
      int size = queue.size();
      for (int i = 0; i < size; i++) {
        SootMethod current = queue.poll();
        for (Iterator<Edge> it = cg.edgesOutOf(current); it.hasNext(); ) {
          Edge edge = it.next();
          SootMethod target = edge.getTgt().method();
          if (visited.add(target)) {
            queue.add(target);
            subgraphNodes.add(target);
          }
        }

        for (Iterator<Edge> it = cg.edgesInto(current); it.hasNext(); ) {
          Edge edge = it.next();
          SootMethod source = edge.getSrc().method();
          if (visited.add(source)) {
            queue.add(source);
            subgraphNodes.add(source);
          }
        }
      }
      k--;
    }

    Set<GraphEdge<SootMethodNode>> edges = new HashSet<>();
    for (SootMethod node : subgraphNodes) {
      for (Iterator<Edge> it = cg.edgesOutOf(node); it.hasNext(); ) {
        Edge edge = it.next();
        SootMethod target = edge.getTgt().method();
        if (subgraphNodes.contains(target)) {
          SootMethodNode src = new SootMethodNode(node);
          SootMethodNode tgt = new SootMethodNode(target);
          GraphEdge<SootMethodNode> graphEdge = new GraphEdge<>(src, tgt);
          edges.add(graphEdge);
        }
      }
    }
    Subgraph<SootMethodNode> subgraph = new Subgraph<>();
    for (GraphEdge<SootMethodNode> edge : edges) {
      subgraph.addEdge(edge);
    }
    if (subgraph.isEmpty()) {
      return;
    }

    Subgraph<SootMethodNode> pruneSubgraph = pruneSubgraph(subgraph, methodSearched);
    if (pruneSubgraph != null) {
      if (pruneSubgraph.isConnected()) {
        pruneSubgraph.drawDotGraph(methodSearched.getName(), outputDir, "Subgraph");

        for (SootMethodNode node : pruneSubgraph.getNodes()) {
          SootMethod method = node.getSootMethod();

          if (method.hasActiveBody()) {
            Body body = method.getActiveBody();
            String methodSignature = method.getSignature().split("\\(")[0];
            String folder = outputDir + "/Subgraph/functions";
            new File(folder).mkdirs();
            String jimpleFileName = folder + "/" + methodSignature + ".jimple";
            try (PrintWriter writer = new PrintWriter(jimpleFileName, "UTF-8")) {
              writer.println(body);
            } catch (IOException exception) {
              throw new UncheckedIOException(
                  "Unable to write Jimple output to " + jimpleFileName, exception);
            }
          }
        }

      } else if (Instrumenter.DEBUG) {
        System.err.println("Subgraph is not connected: " + methodSearched.getSignature());
      }
    }
  }

  public Subgraph<SootMethodNode> pruneSubgraph(
      Subgraph<SootMethodNode> subgraph, SootMethod methodSearched) {
    Subgraph<SootMethodNode> prunedSubgraph = new Subgraph<>();

    Set<GraphEdge<SootMethodNode>> edges = subgraph.getEdges();
    Set<GraphEdge<SootMethodNode>> edgeRemove = new HashSet<>();
    for (GraphEdge<SootMethodNode> edge : edges) {
      SootMethodNode src = edge.getSrc();
      SootMethodNode tgt = edge.getTgt();
      if (!tgt.toString().equals(methodSearched.getSignature()) && isTPL(src.getSootMethod())) {
        edgeRemove.add(edge);
      }
    }

    for (GraphEdge<SootMethodNode> edge : edges) {
      if (!edgeRemove.contains(edge)) {
        prunedSubgraph.addEdge(edge);
      }
    }

    for (SootMethodNode node : prunedSubgraph.getNodes()) {
      if (node.toString().equals(methodSearched.getSignature())) {
        return prunedSubgraph;
      }
    }

    // The searched method was removed while pruning third-party-library roots.
    return null;
  }

  public boolean isTPL(SootMethod method) {
    SootClass sootClass = method.getDeclaringClass();
    return !Scene.v().getApplicationClasses().contains(sootClass);
  }
}
