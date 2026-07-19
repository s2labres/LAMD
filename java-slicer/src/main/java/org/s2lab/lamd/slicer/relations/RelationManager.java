/*
 * Copyright 2025 The LAMD Authors
 * SPDX-License-Identifier: Apache-2.0
 */
package org.s2lab.lamd.slicer.relations;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

public class RelationManager {
  private final Set<Relation> relations = new HashSet<>();
  protected String filePath;

  public RelationManager(String filePath) {
    this.filePath = filePath;
  }

  public void addRelation(Relation relation) {
    relations.add(relation);
  }

  public void saveToTxt() {
    File folder = new File(filePath).getParentFile();
    if (!folder.exists()) {
      folder.mkdirs();
    }
    try (FileWriter writer = new FileWriter(filePath)) {
      for (String relation : formattedRelations()) {
        writer.write(relation + "\n");
      }
    } catch (IOException e) {
      throw new UncheckedIOException("Unable to write relations to " + filePath, e);
    }
  }

  private Set<String> formattedRelations() {
    Set<String> formatted = new TreeSet<>();
    for (Relation relation : relations) {
      formatted.add(relation.toFormattedString());
    }
    return formatted;
  }
}
