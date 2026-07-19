/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import java.io.File;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import soot.util.dot.DotGraph;

public class Subgraph<T> {
  private final Set<GraphEdge<T>> edges;
  private final Set<T> nodes;

  public Subgraph() {
    this.edges = new HashSet<>();
    this.nodes = new HashSet<>();
  }

  public void addNode(T node) {
    nodes.add(node);
  }

  public void addEdge(GraphEdge<T> edge) {
    edges.add(edge);
    nodes.add(edge.getSrc());
    nodes.add(edge.getTgt());
  }

  public Set<GraphEdge<T>> getEdges() {
    return edges;
  }

  public Set<T> getNodes() {
    return nodes;
  }

  public boolean containsEdge(GraphEdge<T> edge) {
    return edges.contains(edge);
  }

  public boolean containsNode(T node) {
    return nodes.contains(node);
  }

  public boolean isEmpty() {
    return nodes.isEmpty();
  }

  public int edgeSize() {
    return edges.size();
  }

  public int nodeSize() {
    return nodes.size();
  }

  public void clear() {
    edges.clear();
    nodes.clear();
  }

  public String drawDotGraph(String name, String outputDir, String type) {
    outputDir = outputDir + "/" + type;
    File folder = new File(outputDir);
    if (!folder.exists()) {
      folder.mkdirs();
    }

    String dotFileName = outputDir + "/" + name + ".dot";
    File file = new File(dotFileName);
    if (file.exists()) {
      return dotFileName;
    }

    DotGraph dotGraph = new DotGraph("subgraph");

    if (nodeSize() > 1) {
      removeIsolatedNodes();
    }
    for (T node : nodes) {
      dotGraph.drawNode(node.toString());
    }

    for (GraphEdge<T> edge : edges) {
      dotGraph.drawEdge(edge.getSrc().toString(), edge.getTgt().toString());
    }

    dotGraph.plot(dotFileName);

    return dotFileName;
  }

  private void removeIsolatedNodes() {
    if (nodeSize() == 1) {
      return;
    }
    Set<T> isolatedNodes = new HashSet<>();
    for (T node : nodes) {
      boolean hasEdge = false;
      for (GraphEdge<T> edge : edges) {
        if (edge.getSrc().equals(node) || edge.getTgt().equals(node)) {
          hasEdge = true;
          break;
        }
      }
      if (!hasEdge) {
        isolatedNodes.add(node);
      }
    }
    nodes.removeAll(isolatedNodes);
  }

  public boolean isConnected() {
    if (edges.isEmpty()) {
      return true;
    }

    Set<T> visited = new HashSet<>();
    List<T> toVisit = new ArrayList<>();

    // Start traversal from an arbitrary node
    T startNode = nodes.iterator().next();
    toVisit.add(startNode);

    while (!toVisit.isEmpty()) {
      T current = toVisit.remove(0); // BFS
      visited.add(current);

      // Traverse all connected nodes (both directions)
      for (GraphEdge<T> edge : edges) {
        if (edge.getSrc().equals(current) && !visited.contains(edge.getTgt())) {
          toVisit.add(edge.getTgt());
        } else if (edge.getTgt().equals(current) && !visited.contains(edge.getSrc())) {
          toVisit.add(edge.getSrc());
        }
      }
    }

    // The graph is connected if all nodes are visited
    return visited.size() == nodes.size();
  }

  @Override
  public String toString() {
    return edges.toString();
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == null) {
      return false;
    }
    if (!Subgraph.class.isAssignableFrom(obj.getClass())) {
      return false;
    }
    final Subgraph<?> other = (Subgraph<?>) obj;

    return this.edges.equals(other.edges);
  }

  @Override
  public int hashCode() {
    return edges.hashCode();
  }
}
