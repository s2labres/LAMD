/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.*;
import org.graphstream.stream.GraphParseException;
import org.s2lab.lamd.slicer.relations.*;
import soot.*;
import soot.jimple.*;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.ExceptionalBlockGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;

public class Slicer {
  private final GraphUtility graphUtility = new GraphUtility();

  public boolean extractMethodSlice(
      CallGraph callGraph,
      SootMethod methodContaining,
      SootMethod methodSearched,
      int k,
      int index,
      int featureIndex)
      throws IOException, GraphParseException {
    String output_dir = Instrumenter.output_dir + "/" + featureIndex + "/" + index;
    Subgraph<String> subCallGraph = new Subgraph<>();
    subCallGraph =
        backwardSlice(
            callGraph,
            methodContaining,
            methodSearched,
            methodContaining.getActiveBody(),
            subCallGraph,
            output_dir,
            k);
    if (!subCallGraph.isEmpty()) {
      subCallGraph.drawDotGraph(methodSearched.getName(), output_dir, "CallGraph");
      return true;
    }
    return false;
  }

  public Subgraph<String> backwardSlice(
      CallGraph callGraph,
      SootMethod method_containing,
      SootMethod method_searched,
      Body body,
      Subgraph<String> subCallGraph,
      String outputDir,
      int k)
      throws IOException, GraphParseException {
    return backwardSlice(
        callGraph, method_containing, method_searched, body, subCallGraph, outputDir, k, true);
  }

  private Subgraph<String> backwardSlice(
      CallGraph callGraph,
      SootMethod method_containing,
      SootMethod method_searched,
      Body body,
      Subgraph<String> subCallGraph,
      String outputDir,
      int remainingContextHops,
      boolean resolvingVariables)
      throws IOException, GraphParseException {
    ExceptionalUnitGraph CFG = new ExceptionalUnitGraph(body);
    ExceptionalBlockGraph BFG = new ExceptionalBlockGraph(CFG);

    List<Unit> matchingCallsites = findMatchingCallsites(CFG, method_searched);

    for (int callsiteIndex = 0; callsiteIndex < matchingCallsites.size(); callsiteIndex++) {
      Unit unit = matchingCallsites.get(callsiteIndex);
      String method_containing_name = method_containing.getSignature().substring(1).split("\\(")[0];
      String method_searched_name = method_searched.getSignature().substring(1).split("\\(")[0];
      String slice_name =
          sliceName(method_containing_name, matchingCallsites.size(), callsiteIndex);

      RelationManager relationManager =
          new RelationManager(outputDir + "/Relation/" + slice_name + ".txt");
      Map<Unit, Set<String>> varMap = getVarMap(unit, CFG, relationManager);

      // Conditional (indirect) relevance is collected while walking
      // predecessor statements in getVarMap.

      // draw call graph
      subCallGraph.addNode(method_containing_name);
      if (subCallGraph.containsNode(method_searched_name)) {
        subCallGraph.addEdge(new GraphEdge<>(method_containing_name, method_searched_name));
      }

      // Resolve parameters across callers without consuming the context-hop budget. Once all
      // relevant variables are defined in the current method, switch to the bounded context phase.
      Unit head = CFG.getHeads().get(0);
      List<Type> paramTypes = method_containing.getParameterTypes();
      boolean hasUnresolvedVariables =
          !paramTypes.isEmpty()
              && head instanceof IdentityStmt
              && varMap.containsKey(head)
              && !varMap.get(head).isEmpty();
      if (resolvingVariables && hasUnresolvedVariables) {
        recurseIntoCallers(
            callGraph, method_containing, subCallGraph, outputDir, remainingContextHops, true);
      } else if (remainingContextHops > 0) {
        recurseIntoCallers(
            callGraph, method_containing, subCallGraph, outputDir, remainingContextHops - 1, false);
      }

      List<Unit> slices = getSlices(unit, CFG, varMap);

      JimpleBody jimpleBody = (JimpleBody) method_containing.retrieveActiveBody();
      outputJimple(jimpleBody, method_containing_name, outputDir);

      Subgraph<String> sliceGraph = graphUtility.buildSliceGraph(slices, CFG);
      graphUtility.drawBlockGraph(BFG, method_containing_name, outputDir);
      String sliceDotFilePath = sliceGraph.drawDotGraph(slice_name, outputDir, "SliceGraph");
      graphUtility.combineNodes(sliceDotFilePath);
    }
    return subCallGraph;
  }

  private void recurseIntoCallers(
      CallGraph callGraph,
      SootMethod methodContaining,
      Subgraph<String> subCallGraph,
      String outputDir,
      int remainingContextHops,
      boolean resolvingVariables)
      throws IOException, GraphParseException {
    String methodContainingName = methodContaining.getSignature().substring(1).split("\\(")[0];
    for (SootMethod callerFunction : getCallerFunctions(callGraph, methodContaining)) {
      if (!callerFunction.hasActiveBody()) {
        continue;
      }

      String callerName = callerFunction.getSignature().substring(1).split("\\(")[0];
      if (subCallGraph.containsNode(callerName)) {
        subCallGraph.addEdge(new GraphEdge<>(callerName, methodContainingName));
        continue;
      }

      backwardSlice(
          callGraph,
          callerFunction,
          methodContaining,
          callerFunction.getActiveBody(),
          subCallGraph,
          outputDir,
          remainingContextHops,
          resolvingVariables);
    }
  }

  static List<Unit> findMatchingCallsites(Iterable<Unit> units, SootMethod methodSearched) {
    List<Unit> matchingCallsites = new ArrayList<>();
    for (Unit unit : units) {
      Stmt statement = (Stmt) unit;
      if (statement.containsInvokeExpr()
          && statement
              .getInvokeExpr()
              .getMethodRef()
              .getSignature()
              .equals(methodSearched.getSignature())) {
        matchingCallsites.add(unit);
      }
    }
    return matchingCallsites;
  }

  static String sliceName(String methodName, int callsiteCount, int callsiteIndex) {
    return callsiteCount == 1 ? methodName : methodName + "__callsite_" + callsiteIndex;
  }

  public Map<Unit, Set<String>> getVarMap(
      Unit targetUnit, ExceptionalUnitGraph CFG, RelationManager relationManager) {
    Map<Unit, Set<String>> varMap = new HashMap<>();
    ArrayDeque<Unit> worklist = new ArrayDeque<>();
    Set<Unit> visited = new HashSet<>();
    worklist.add(targetUnit);
    visited.add(targetUnit);
    Set<String> directedRelevantVars = new HashSet<>();

    // Direct relevant variables
    while (!worklist.isEmpty()) {
      Unit currUnit = worklist.pop();
      visited.add(currUnit);
      Set<String> locals = new HashSet<>();

      // load locals
      if (currUnit.equals(targetUnit)) {
        // load the variables from the method call
        for (ValueBox use : currUnit.getUseBoxes()) {
          if (use.getValue().toString().matches("^\\$?[a-z]\\d+$")
                  && use.getValue().toString().length() <= 4
              || use.getValue().toString().matches("^parameter\\d+")) {
            locals.add(use.getValue().toString());
            relationManager.addRelation(new DirectRelation(use.getValue().toString()));
            directedRelevantVars.add(use.getValue().toString());
          }
        }
        List<String> argumentVariables = invocationArgumentVariables((Stmt) currUnit);
        if (argumentVariables.size() >= 2) {
          relationManager.addRelation(new ParallelRelation(argumentVariables));
        }
      } else {
        // load the variables from its successors
        for (Unit succ : CFG.getSuccsOf(currUnit)) {
          locals.addAll(varMap.getOrDefault(succ, Collections.emptySet()));
        }
      }

      // Iterate over the units from the end to the beginning to find relevant variables
      if (isRelevantStmt(currUnit, locals)) {
        List<ValueBox> defs = currUnit.getDefBoxes();
        if (!currUnit.equals(targetUnit) && currUnit instanceof DefinitionStmt) {
          List<String> sourceVariables = localUses(currUnit);
          if (sourceVariables.size() >= 2) {
            relationManager.addRelation(new ParallelRelation(sourceVariables));
          }
        }
        for (ValueBox def : defs) {
          locals.remove(def.getValue().toString());
        }
        for (ValueBox use : currUnit.getUseBoxes()) {
          String valueStr = use.getValue().toString();
          if (valueStr.matches("^\\$?[a-z]\\d+$") && valueStr.length() <= 4
              || valueStr.matches("^parameter\\d+")) {
            locals.add(valueStr);
            if (currUnit instanceof IfStmt
                || currUnit instanceof GotoStmt
                || currUnit instanceof SwitchStmt) {
              relationManager.addRelation(new ConditionalRelation(valueStr));
            } else {
              if (!directedRelevantVars.contains(valueStr)) {
                relationManager.addRelation(new TransitiveRelation(valueStr));
                if (!defs.isEmpty()) {
                  for (ValueBox def : defs) {
                    Value value = def.getValue();
                    String derivedVariable;
                    if (value instanceof InstanceFieldRef) {
                      InstanceFieldRef instanceFieldRef = (InstanceFieldRef) value;
                      derivedVariable = instanceFieldRef.getBase().toString();
                    } else {
                      derivedVariable = value.toString();
                    }
                    if (!derivedVariable.equals(valueStr)) {
                      relationManager.addRelation(new DerivedRelation(derivedVariable, valueStr));
                    }
                  }
                }
              }
            }
          }
        }
      }

      varMap.put(currUnit, locals);

      if (locals.isEmpty()) {
        // This predecessor path is irrelevant, but other queued CFG
        // branches may still contribute to the invocation.
        continue;
      }
      for (Unit pred : CFG.getPredsOf(currUnit)) {
        if (visited.add(pred)) {
          worklist.add(pred);
        }
      }
    }

    relationManager.saveToTxt();

    return varMap;
  }

  static List<String> invocationArgumentVariables(Stmt statement) {
    if (!statement.containsInvokeExpr()) {
      return Collections.emptyList();
    }
    Set<String> variables = new TreeSet<>();
    for (Value argument : statement.getInvokeExpr().getArgs()) {
      if (argument instanceof Local) {
        variables.add(argument.toString());
      }
    }
    return new ArrayList<>(variables);
  }

  static List<String> localUses(Unit unit) {
    Set<String> variables = new TreeSet<>();
    for (ValueBox use : unit.getUseBoxes()) {
      if (use.getValue() instanceof Local) {
        variables.add(use.getValue().toString());
      }
    }
    return new ArrayList<>(variables);
  }

  public List<Unit> getSlices(Unit unit, ExceptionalUnitGraph CFG, Map<Unit, Set<String>> varMap) {
    List<Unit> slices = new ArrayList<>();
    Set<Unit> visited = new HashSet<>();
    ArrayDeque<Unit> worklist = new ArrayDeque<>();
    slices.add(unit);
    visited.add(unit);
    worklist.addAll(CFG.getPredsOf(unit));

    while (!worklist.isEmpty()) {
      Unit currUnit = worklist.pop();
      visited.add(currUnit);
      Set<String> succVars = new HashSet<>();

      // load the variables from its successors
      for (Unit succ : CFG.getSuccsOf(currUnit)) {
        succVars.addAll(varMap.getOrDefault(succ, Collections.emptySet()));
      }

      if (succVars.isEmpty()) {
        // Do not terminate traversal of unrelated queued branches.
        continue;
      }

      // check if the current unit is relevant
      if (currUnit instanceof DefinitionStmt) {
        boolean found = false;
        for (ValueBox def : currUnit.getDefBoxes()) {
          for (ValueBox use : def.getValue().getUseBoxes()) {
            if (succVars.contains(use.getValue().toString())) {
              slices.add(0, currUnit);
              found = true;
              break;
            }
          }
          if (!found && succVars.contains(def.getValue().toString())) {
            slices.add(0, currUnit);
            found = true;
          }
          if (found) {
            break;
          }
        }
      } else if (currUnit instanceof IfStmt
          || currUnit instanceof GotoStmt
          || currUnit instanceof SwitchStmt) {
        slices.add(0, currUnit);
      } else {
        for (ValueBox value : currUnit.getUseBoxes()) {
          if (succVars.contains(value.getValue().toString())) {
            slices.add(0, currUnit);
            break;
          }
        }
      }

      List<Unit> preds = CFG.getPredsOf(currUnit);
      for (Unit pred : preds) {
        if (visited.add(pred)) {
          worklist.add(pred);
        }
      }
    }
    return slices;
  }

  public void outputJimple(JimpleBody body, String name, String outputDir) throws IOException {
    outputDir = outputDir + "/code";
    File folder = new File(outputDir);
    if (!folder.exists()) {
      folder.mkdirs();
    }

    String sliceFileName = outputDir + "/" + name + ".jimple";
    try (BufferedWriter writer = new BufferedWriter(new FileWriter(sliceFileName))) {
      writer.write(body.toString());
    }
  }

  public boolean isRelevantStmt(Unit u, Set<String> locals) {
    boolean relevant = false;

    List<ValueBox> defs = u.getDefBoxes();
    List<ValueBox> uses = u.getUseBoxes();
    if (u instanceof AssignStmt) {

      if (!defs.isEmpty()) {
        for (ValueBox def : defs) {
          for (String local : locals) {
            if (def.getValue().toString().contains(local)) {
              relevant = true;
              break;
            }
          }
          if (relevant) {
            break;
          }
        }
      }
    } else if (u instanceof IfStmt || u instanceof GotoStmt || u instanceof SwitchStmt) {
      relevant = true;
    } else {
      for (ValueBox use : uses) {
        for (String local : locals) {
          if (use.getValue().toString().contains(local)) {
            relevant = true;
            break;
          }
        }
        if (relevant) {
          break;
        }
      }
    }

    return relevant;
  }

  public List<SootMethod> getCallerFunctions(CallGraph callGraph, SootMethod method) {
    List<SootMethod> invokingMethods = new ArrayList<>();
    Iterator<Edge> edges = callGraph.edgesInto(method);
    while (edges.hasNext()) {
      Edge edge = edges.next();
      SootMethod invokingMethod = edge.getSrc().method();
      invokingMethods.add(invokingMethod);
    }
    return invokingMethods;
  }
}
