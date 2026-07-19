/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import org.graphstream.graph.Edge;
import org.graphstream.graph.Graph;
import org.graphstream.graph.Node;
import org.graphstream.graph.implementations.SingleGraph;
import org.graphstream.stream.GraphParseException;
import org.graphstream.stream.file.FileSinkDOT;
import soot.Unit;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.UnitGraph;
import soot.util.dot.DotGraph;
import soot.util.dot.DotGraphConstants;
import soot.util.dot.DotGraphEdge;

public class GraphUtility {

  public String getUnitString(Unit unit) {
    return unit + "---" + unit.hashCode();
  }

  public String getBlockString(Block block) {
    return block.toString() + "---" + block.hashCode();
  }

  public Subgraph<String> buildSliceGraph(List<Unit> slices, ExceptionalUnitGraph CFG) {
    Subgraph<String> sliceGraph = new Subgraph<>();
    Set<String> drawnEdges = new HashSet<>();

    // Draw nodes for each Unit in the slice
    for (Unit u : slices) {
      sliceGraph.addNode(getUnitString(u));
    }

    // Draw edges for both successors and predecessors (including transitive connections)
    for (Unit u : slices) {
      // Downward (successor) connections
      connectSuccessors(u, slices, CFG, sliceGraph, drawnEdges);

      // Upward (predecessor) connections
      connectPredecessors(u, slices, CFG, sliceGraph, drawnEdges);
    }

    return sliceGraph;
  }

  private void connectSuccessors(
      Unit u,
      List<Unit> slices,
      ExceptionalUnitGraph CFG,
      Subgraph<String> sliceGraph,
      Set<String> drawnEdges) {
    Set<Unit> visited = new HashSet<>();

    ArrayDeque<Unit> toVisit = new ArrayDeque<>(CFG.getSuccsOf(u));

    while (!toVisit.isEmpty()) {
      Unit succ = toVisit.pop();
      if (visited.contains(succ)) {
        continue;
      }
      visited.add(succ);

      // If the successor is in the slice, connect it to the current unit
      if (slices.contains(succ)) {
        String edge = getUnitString(u) + "->" + getUnitString(succ);
        if (!drawnEdges.contains(edge)) {
          sliceGraph.addEdge(new GraphEdge<>(getUnitString(u), getUnitString(succ)));
          drawnEdges.add(edge);
        }
      } else {
        // Otherwise, keep traversing through the CFG
        toVisit.addAll(CFG.getSuccsOf(succ));
      }
    }
  }

  private void connectPredecessors(
      Unit u,
      List<Unit> slices,
      ExceptionalUnitGraph CFG,
      Subgraph<String> sliceGraph,
      Set<String> drawnEdges) {
    Set<Unit> visited = new HashSet<>();

    ArrayDeque<Unit> toVisit = new ArrayDeque<>(CFG.getPredsOf(u));

    while (!toVisit.isEmpty()) {
      Unit pred = toVisit.pop();
      if (visited.contains(pred)) {
        continue;
      }
      visited.add(pred);

      // If the predecessor is in the slice, connect it to the current unit
      if (slices.contains(pred)) {
        String edge = getUnitString(pred) + "->" + getUnitString(u);
        if (!drawnEdges.contains(edge)) {
          sliceGraph.addEdge(new GraphEdge<>(getUnitString(pred), getUnitString(u)));
          drawnEdges.add(edge);
        }
      } else {
        // Otherwise, keep traversing through the CFG
        toVisit.addAll(CFG.getPredsOf(pred));
      }
    }
  }

  public void drawUnitGraph(UnitGraph unitGraph, String methodSignature, String outputDir) {
    DotGraph cfgDot = new DotGraph("cfg");
    for (Unit unit : unitGraph) {
      cfgDot.drawNode(getUnitString(unit));
    }
    for (Unit unit : unitGraph) {
      for (Unit succ : unitGraph.getSuccsOf(unit)) {
        DotGraphEdge edge = cfgDot.drawEdge(getUnitString(unit), getUnitString(succ));
        edge.setStyle(DotGraphConstants.EDGE_STYLE_DOTTED);
      }
    }

    outputDir = outputDir + "/cfg";
    File folder = new File(outputDir);
    if (!folder.exists()) {
      folder.mkdirs();
    }
    cfgDot.plot(outputDir + "/" + methodSignature + ".dot");
    if (Instrumenter.DEBUG) {
      System.err.println("Created CFG: " + "/cfg/" + methodSignature + ".dot");
    }
  }

  public void drawBlockGraph(BlockGraph blockGraph, String methodSignature, String outputDir) {
    DotGraph cfgDot = new DotGraph("cfg");
    for (Block block : blockGraph) {
      cfgDot.drawNode(getBlockString(block));
    }
    for (Block block : blockGraph) {
      for (Block succ : blockGraph.getSuccsOf(block)) {
        DotGraphEdge edge = cfgDot.drawEdge(getBlockString(block), getBlockString(succ));
        edge.setStyle(DotGraphConstants.EDGE_STYLE_DOTTED);
      }
    }

    outputDir = outputDir + "/cfg";
    File folder = new File(outputDir);
    if (!folder.exists()) {
      folder.mkdirs();
    }
    cfgDot.plot(outputDir + "/" + methodSignature + ".dot");
    if (Instrumenter.DEBUG) {
      System.err.println("Created CFG: " + "/cfg/" + methodSignature + ".dot");
    }
  }

  public boolean containsControlFlow(Node node) {
    String[] instructions = node.getId().split("\n");
    for (String in : instructions) {
      if (in.startsWith("if")
          || in.startsWith("goto")
          || in.startsWith("return")
          || in.startsWith("switch")
          || in.startsWith("tableswitch")
          || in.startsWith("lookupswitch")) {
        return true;
      }
    }
    return false;
  }

  public void combineNodes(String dotFile) throws IOException, GraphParseException {
    // Load the DOT file
    Graph graph = new SingleGraph("SliceGraph", true, true);
    graph.read(dotFile);

    List<Node> nodesToRemove = new ArrayList<>();

    List<Node> nodesToProcess = new ArrayList<>();
    for (Node node : graph) {
      nodesToProcess.add(node);
    }

    // Iterate over all nodes
    while (!nodesToProcess.isEmpty()) {
      Node node = nodesToProcess.remove(0);
      if (nodesToRemove.contains(node)) {
        continue;
      }

      if (containsControlFlow(node)) {
        continue;
      }

      // Check if the node has out-degree 1 and in-degree 1
      if (node.getOutDegree() == 1) {

        Node next = node.getLeavingEdge(0).getTargetNode();

        if (Objects.equals(node.getId(), next.getId())) {
          continue;
        }

        if (next.getInDegree() == 1) {
          Node combinedNode = graph.addNode(node.getId() + "\n" + next.getId());

          graph.removeEdge("(" + node.getId() + ";" + next.getId() + ")");

          List<Node> preds =
              node.enteringEdges().map(Edge::getSourceNode).collect(Collectors.toList());
          for (Node pred : preds) {
            String newEdge = "(" + pred.getId() + ";" + combinedNode.getId() + ")";
            graph.addEdge(newEdge, pred, combinedNode, true);
            graph.removeEdge("(" + pred.getId() + ";" + node.getId() + ")");
          }

          List<Node> nextSuccs =
              next.leavingEdges().map(Edge::getTargetNode).collect(Collectors.toList());
          for (Node nextSucc : nextSuccs) {
            graph.addEdge(
                "(" + combinedNode.getId() + ";" + nextSucc.getId() + ")",
                combinedNode,
                nextSucc,
                true);
            graph.removeEdge("(" + next.getId() + ";" + nextSucc.getId() + ")");
          }

          nodesToRemove.add(node);
          nodesToRemove.add(next);
          nodesToProcess.add(combinedNode);
        }
      }
    }

    // Remove the nodes that were combined
    for (Node node : nodesToRemove) {
      graph.removeNode(node);
    }

    // Write the modified graph to the original DOT file
    FileSinkDOT sink = new FileSinkDOT(true);
    sink.writeAll(graph, dotFile);
  }
}
