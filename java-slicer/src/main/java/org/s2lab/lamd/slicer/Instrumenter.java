/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.commons.io.FileUtils;
import soot.Scene;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.options.Options;

/** Command-line entry point for the context-extraction stage of LAMD. */
public final class Instrumenter {
  private static final int MAX_API_WORKERS = 16;

  protected static String apkPath = "";
  public static String output_dir = "";
  protected static String jarsPath = "";
  public static String sensitiveAPIListPath = "";
  protected static int k = 0;
  public static int output_format = Options.output_format_dex;
  public static boolean DEBUG = false;
  public static boolean msdroid = false;

  private Instrumenter() {}

  public static void main(String[] args) {
    try {
      int sliceCount = run(args);
      // The Python wrapper deliberately parses the final stdout integer.
      System.out.println(sliceCount);
    } catch (Exception exception) {
      System.err.println("LAMD slicing failed: " + exception.getMessage());
      if (DEBUG) {
        exception.printStackTrace(System.err);
      }
      System.exit(1);
    }
  }

  static int run(String[] args) throws IOException, ExecutionException {
    parseArguments(args);
    long startTime = System.currentTimeMillis();

    File apkFile = new File(apkPath);
    File outputRoot = new File(output_dir);
    if (!outputRoot.exists() && !outputRoot.mkdirs()) {
      throw new IOException("Cannot create output directory: " + outputRoot);
    }
    String apkName = apkFile.getName();
    int extension = apkName.lastIndexOf('.');
    String sampleName = extension > 0 ? apkName.substring(0, extension) : apkName;
    File sampleOutput = new File(outputRoot, sampleName);
    if (sampleOutput.exists()) {
      FileUtils.deleteDirectory(sampleOutput);
    }
    if (!sampleOutput.mkdirs()) {
      throw new IOException("Cannot create sample output directory: " + sampleOutput);
    }
    output_dir = sampleOutput.getAbsolutePath();

    SootUtility utility = new SootUtility();
    List<String> sensitiveApis = utility.getSensitiveAPIList(sensitiveAPIListPath);
    utility.initFlowDroid(apkPath);
    CallGraph callGraph = Scene.v().getCallGraph();

    int workers =
        Math.max(1, Math.min(MAX_API_WORKERS, Runtime.getRuntime().availableProcessors()));
    ExecutorService executor = Executors.newFixedThreadPool(workers);
    List<Future<Integer>> futures = new ArrayList<>();
    try {
      for (int index = 0; index < sensitiveApis.size(); index++) {
        final int featureIndex = index;
        String feature = sensitiveApis.get(index).replace('/', '.');
        String[] parts = feature.split(";->", 2);
        if (parts.length != 2 || parts[0].isEmpty() || parts[1].isEmpty()) {
          throw new IllegalArgumentException(
              "Malformed sensitive API at line " + (index + 1) + ": " + feature);
        }
        final String className = parts[0];
        final String methodName = parts[1];
        futures.add(
            executor.submit(
                () ->
                    new ApiCallExtractor()
                        .extract_features(callGraph, className, methodName, featureIndex, k)));
      }
    } finally {
      executor.shutdown();
    }

    int totalSlices = 0;
    for (Future<Integer> future : futures) {
      try {
        totalSlices += future.get();
      } catch (InterruptedException exception) {
        Thread.currentThread().interrupt();
        throw new ExecutionException("Interrupted while waiting for API slicing", exception);
      }
    }

    if (DEBUG) {
      double seconds = (System.currentTimeMillis() - startTime) / 1000.0;
      System.err.printf(
          Locale.ROOT, "Slicing completed in %.3f seconds (%d slices)%n", seconds, totalSlices);
    }
    if (totalSlices == 0) {
      FileUtils.deleteDirectory(sampleOutput);
    }
    return totalSlices;
  }

  private static void parseArguments(String[] args) {
    if (args.length != 7) {
      throw new IllegalArgumentException(
          "Usage: java -jar lamd-slicer.jar <apk> <output-dir> "
              + "<android-platforms> <sensitive-api-list> <k> <msdroid> <debug>");
    }
    apkPath = args[0];
    output_dir = args[1];
    jarsPath = args[2];
    sensitiveAPIListPath = args[3];
    k = Integer.parseInt(args[4]);
    if (k < 0) {
      throw new IllegalArgumentException("k must be non-negative");
    }
    msdroid = parseBoolean(args[5], "msdroid");
    DEBUG = parseBoolean(args[6], "debug");

    if (!new File(apkPath).isFile()) {
      throw new IllegalArgumentException("APK not found: " + apkPath);
    }
    if (!new File(jarsPath).isDirectory()) {
      throw new IllegalArgumentException("Android platforms directory not found: " + jarsPath);
    }
    if (!new File(sensitiveAPIListPath).isFile()) {
      throw new IllegalArgumentException("Sensitive API list not found: " + sensitiveAPIListPath);
    }
  }

  private static boolean parseBoolean(String value, String name) {
    if (!"true".equalsIgnoreCase(value) && !"false".equalsIgnoreCase(value)) {
      throw new IllegalArgumentException(name + " must be true or false");
    }
    return Boolean.parseBoolean(value);
  }
}
