/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Parses the Java method-reference syntax documented for dynamic instrumentation. */
public final class JavaMethodReference {
  private static final String[] PRIMITIVE_TYPES = {
    "boolean", "byte", "short", "int", "long", "char", "float", "double"
  };
  private static final String[] KEYWORDS = {
    "abstract",
    "assert",
    "boolean",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "class",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extends",
    "final",
    "finally",
    "float",
    "for",
    "goto",
    "if",
    "implements",
    "import",
    "instanceof",
    "int",
    "interface",
    "long",
    "native",
    "new",
    "package",
    "private",
    "protected",
    "public",
    "return",
    "short",
    "static",
    "strictfp",
    "super",
    "switch",
    "synchronized",
    "this",
    "throw",
    "throws",
    "transient",
    "try",
    "void",
    "volatile",
    "while",
    "true",
    "false",
    "null",
    "_"
  };

  private final String classSelector;
  private final String methodSelector;
  private final boolean classGlob;
  private final boolean methodGlob;
  private final boolean hasParameterList;
  private final List<String> parameterTypes;

  private JavaMethodReference(
      String classSelector,
      String methodSelector,
      boolean classGlob,
      boolean methodGlob,
      boolean hasParameterList,
      List<String> parameterTypes) {
    this.classSelector = classSelector;
    this.methodSelector = methodSelector;
    this.classGlob = classGlob;
    this.methodGlob = methodGlob;
    this.hasParameterList = hasParameterList;
    this.parameterTypes = Collections.unmodifiableList(parameterTypes);
  }

  public static JavaMethodReference parse(String reference) {
    if (reference == null || reference.isEmpty()) {
      throw invalid("reference must not be empty");
    }
    if (containsWhitespace(reference)) {
      throw invalid("whitespace is not allowed");
    }

    int separator = reference.indexOf('#');
    if (separator <= 0 || separator != reference.lastIndexOf('#')) {
      throw invalid("reference must contain exactly one '#' separator");
    }

    String classSelector = reference.substring(0, separator);
    String methodAndParameters = reference.substring(separator + 1);
    validateClassSelector(classSelector);

    int openParen = methodAndParameters.indexOf('(');
    int closeParen = methodAndParameters.indexOf(')');
    boolean hasParameterList = openParen >= 0 || closeParen >= 0;
    String methodSelector;
    List<String> parameterTypes = new ArrayList<>();
    if (!hasParameterList) {
      methodSelector = methodAndParameters;
    } else {
      if (openParen <= 0
          || closeParen != methodAndParameters.length() - 1
          || closeParen < openParen
          || methodAndParameters.indexOf('(', openParen + 1) >= 0
          || methodAndParameters.indexOf(')', closeParen + 1) >= 0) {
        throw invalid("parameter list must be enclosed in one final pair of parentheses");
      }
      methodSelector = methodAndParameters.substring(0, openParen);
      String parameters = methodAndParameters.substring(openParen + 1, closeParen);
      if (!parameters.isEmpty()) {
        String[] entries = parameters.split(",", -1);
        for (String entry : entries) {
          validateParameterType(entry);
          parameterTypes.add(entry);
        }
      }
    }
    boolean methodGlob = validateMethodSelector(methodSelector);

    return new JavaMethodReference(
        classSelector,
        methodSelector,
        classSelector.indexOf('*') >= 0 || classSelector.indexOf('?') >= 0,
        methodGlob,
        hasParameterList,
        parameterTypes);
  }

  public String classSelector() {
    return classSelector;
  }

  public String methodSelector() {
    return methodSelector;
  }

  public boolean isClassGlob() {
    return classGlob;
  }

  public boolean isMethodGlob() {
    return methodGlob;
  }

  public boolean hasParameterList() {
    return hasParameterList;
  }

  public List<String> parameterTypes() {
    return parameterTypes;
  }

  private static void validateClassSelector(String selector) {
    if (selector.isEmpty()) {
      throw invalid("class selector must not be empty");
    }
    boolean hasGlob = selector.indexOf('*') >= 0 || selector.indexOf('?') >= 0;
    if (!hasGlob) {
      validateFullyQualifiedName(selector, "class selector");
      return;
    }

    int segmentStart = 0;
    for (int index = 0; index <= selector.length(); index++) {
      if (index == selector.length() || selector.charAt(index) == '.') {
        if (index == segmentStart) {
          throw invalid("class selector must use non-empty name components");
        }
        validateGlobIdentifier(selector.substring(segmentStart, index), "class selector");
        segmentStart = index + 1;
      }
    }
  }

  private static boolean validateMethodSelector(String selector) {
    if (selector.isEmpty()) {
      throw invalid("method selector must not be empty");
    }
    boolean hasGlob = selector.indexOf('*') >= 0 || selector.indexOf('?') >= 0;
    if (hasGlob) {
      validateGlobIdentifier(selector, "method selector");
    } else if (!isIdentifier(selector)) {
      throw invalid("method selector must be a Java identifier or contain '*' or '?' globs");
    }
    return hasGlob;
  }

  private static void validateParameterType(String parameter) {
    if (parameter.isEmpty()) {
      throw invalid("parameter types must not be empty");
    }

    String baseType = parameter;
    while (baseType.endsWith("[]")) {
      baseType = baseType.substring(0, baseType.length() - 2);
    }
    if (baseType.isEmpty() || baseType.indexOf('[') >= 0 || baseType.indexOf(']') >= 0) {
      throw invalid("parameter types must use trailing '[]' array dimensions");
    }
    if ("void".equals(baseType)) {
      throw invalid("void is not a parameter type");
    }
    if (!isPrimitive(baseType)) {
      validateFullyQualifiedName(baseType, "parameter type");
    }
  }

  private static boolean isPrimitive(String value) {
    for (String primitive : PRIMITIVE_TYPES) {
      if (primitive.equals(value)) {
        return true;
      }
    }
    return false;
  }

  private static void validateQualifiedName(String name, String description) {
    if (name.isEmpty()) {
      throw invalid(description + " must not be empty");
    }
    String[] components = name.split("\\.", -1);
    for (String component : components) {
      if (!isIdentifier(component)) {
        throw invalid(description + " must be a fully qualified Java name");
      }
    }
  }

  private static void validateFullyQualifiedName(String name, String description) {
    validateQualifiedName(name, description);
    if (name.indexOf('.') < 0) {
      throw invalid(description + " must be fully qualified");
    }
  }

  private static void validateGlobIdentifier(String pattern, String description) {
    if (pattern.isEmpty()) {
      throw invalid(description + " must not be empty");
    }
    int position = 0;
    boolean first = true;
    while (position < pattern.length()) {
      int codePoint = pattern.codePointAt(position);
      if (codePoint == '*' || codePoint == '?') {
        first = false;
      } else if (first) {
        if (!Character.isJavaIdentifierStart(codePoint)) {
          throw invalid(description + " contains an invalid Java identifier character");
        }
        first = false;
      } else if (!Character.isJavaIdentifierPart(codePoint)) {
        throw invalid(description + " contains an invalid Java identifier character");
      }
      position += Character.charCount(codePoint);
    }
  }

  private static boolean isIdentifier(String value) {
    if (value.isEmpty() || isKeyword(value)) {
      return false;
    }
    int position = 0;
    int firstCodePoint = value.codePointAt(position);
    if (!Character.isJavaIdentifierStart(firstCodePoint)) {
      return false;
    }
    position += Character.charCount(firstCodePoint);
    while (position < value.length()) {
      int codePoint = value.codePointAt(position);
      if (!Character.isJavaIdentifierPart(codePoint)) {
        return false;
      }
      position += Character.charCount(codePoint);
    }
    return true;
  }

  private static boolean isKeyword(String value) {
    for (String keyword : KEYWORDS) {
      if (keyword.equals(value)) {
        return true;
      }
    }
    return false;
  }

  private static boolean containsWhitespace(String value) {
    for (int position = 0; position < value.length(); ) {
      int codePoint = value.codePointAt(position);
      if (Character.isWhitespace(codePoint)) {
        return true;
      }
      position += Character.charCount(codePoint);
    }
    return false;
  }

  private static IllegalArgumentException invalid(String message) {
    return new IllegalArgumentException("invalid Java method reference: " + message);
  }
}
