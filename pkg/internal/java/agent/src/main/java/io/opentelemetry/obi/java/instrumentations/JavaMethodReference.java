/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java.instrumentations;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

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
  private final Style style;
  private final String methodSelector;
  private final boolean classGlob;
  private final boolean methodGlob;
  private final boolean hasParameterList;
  private final List<String> parameterTypes;
  private final String descriptor;
  private final boolean fullDescriptor;

  private enum Style {
    INTERNAL,
    BINARY,
    SOURCE
  }

  private JavaMethodReference(
      String classSelector,
      Style style,
      String methodSelector,
      boolean classGlob,
      boolean methodGlob,
      boolean hasParameterList,
      List<String> parameterTypes,
      String descriptor,
      boolean fullDescriptor) {
    this.classSelector = classSelector;
    this.style = style;
    this.methodSelector = methodSelector;
    this.classGlob = classGlob;
    this.methodGlob = methodGlob;
    this.hasParameterList = hasParameterList;
    this.parameterTypes = Collections.unmodifiableList(parameterTypes);
    this.descriptor = descriptor;
    this.fullDescriptor = fullDescriptor;
  }

  public static JavaMethodReference parse(String reference) {
    if (reference == null || reference.isEmpty()) {
      throw invalid("reference must not be empty");
    }
    if (containsWhitespace(reference)) {
      throw invalid("whitespace is not allowed");
    }

    Style style;
    String classSelector;
    String methodAndParameters;
    int separator;
    if ((separator = reference.indexOf('#')) > 0 && separator == reference.lastIndexOf('#')) {
      style = Style.SOURCE;
      classSelector = reference.substring(0, separator);
      methodAndParameters = reference.substring(separator + 1);
      validateClassSelector(classSelector, style);
    } else if ((separator = reference.indexOf("::")) > 0
        && separator == reference.lastIndexOf("::")) {
      style = Style.BINARY;
      classSelector = reference.substring(0, separator);
      methodAndParameters = reference.substring(separator + 2);
      validateClassSelector(classSelector, style);
    } else {
      separator = reference.lastIndexOf('.');
      if (separator <= 0) throw invalid("reference must contain a class and method selector");
      style = Style.INTERNAL;
      classSelector = reference.substring(0, separator);
      methodAndParameters = reference.substring(separator + 1);
      validateClassSelector(classSelector, style);
    }

    int openParen = methodAndParameters.indexOf('(');
    int closeParen = methodAndParameters.indexOf(')');
    boolean hasParameterList = openParen >= 0 || closeParen >= 0;
    String methodSelector;
    List<String> parameterTypes = new ArrayList<>();
    String descriptor = null;
    boolean fullDescriptor = false;
    if (!hasParameterList) {
      methodSelector = methodAndParameters;
    } else {
      if (openParen <= 0
          || closeParen < openParen
          || methodAndParameters.indexOf('(', openParen + 1) >= 0
          || methodAndParameters.indexOf(')', closeParen + 1) >= 0) {
        throw invalid("parameter list must be enclosed in one final pair of parentheses");
      }
      methodSelector = methodAndParameters.substring(0, openParen);
      String parameters = methodAndParameters.substring(openParen + 1, closeParen);
      String suffix = methodAndParameters.substring(closeParen + 1);
      if (style != Style.SOURCE) {
        if ((parameters + suffix).indexOf('*') >= 0 || (parameters + suffix).indexOf('?') >= 0) {
          throw invalid("JVM descriptors do not support globs");
        }
        descriptor = "(" + parameters + ")" + (suffix.isEmpty() ? "V" : suffix);
        try {
          validateMethodDescriptor(descriptor);
          if (!suffix.isEmpty()) fullDescriptor = true;
        } catch (RuntimeException error) {
          throw invalid("invalid JVM method descriptor");
        }
      } else {
        if (!suffix.isEmpty()) throw invalid("source references do not accept a return descriptor");
        if (!parameters.isEmpty()) {
          String[] entries = parameters.split(",", -1);
          for (String entry : entries) {
            validateParameterType(entry);
            parameterTypes.add(entry);
          }
        }
      }
    }
    boolean methodGlob = validateMethodSelector(methodSelector);

    return new JavaMethodReference(
        classSelector,
        style,
        methodSelector,
        classSelector.indexOf('*') >= 0 || classSelector.indexOf('?') >= 0,
        methodGlob,
        hasParameterList,
        parameterTypes,
        descriptor,
        fullDescriptor);
  }

  public boolean matchesClass(String internalName, String binaryName, String canonicalName) {
    if (style == Style.INTERNAL) return glob(classSelector, internalName);
    if (style == Style.BINARY) return glob(classSelector, binaryName);
    return glob(classSelector, canonicalName) || glob(classSelector, binaryName);
  }

  public boolean matchesMethod(
      String name,
      String[] canonicalParams,
      String[] binaryParams,
      String[] parameterDescriptors,
      String returnDescriptor,
      boolean bridge) {
    if (!glob(methodSelector, name)) return false;
    if (descriptor == null && !hasParameterList) return !bridge;
    if (descriptor != null) {
      if (bridge && (!fullDescriptor || classGlob || methodGlob)) return false;
      StringBuilder actual = new StringBuilder("(");
      for (String parameter : parameterDescriptors) actual.append(parameter);
      actual.append(')').append(returnDescriptor);
      if (fullDescriptor) return descriptor.equals(actual.toString());
      return descriptor
              .substring(0, descriptor.indexOf(")") + 1)
              .equals(actual.substring(0, actual.indexOf(")") + 1))
          && !bridge;
    }
    if (bridge || parameterTypes.size() != canonicalParams.length) return false;
    for (int i = 0; i < parameterTypes.size(); i++) {
      if (!parameterTypes.get(i).equals(canonicalParams[i])
          && !parameterTypes.get(i).equals(binaryParams[i])) return false;
    }
    return true;
  }

  private static boolean glob(String pattern, String value) {
    if (pattern == null || value == null) return false;
    StringBuilder regex = new StringBuilder();
    for (int i = 0; i < pattern.length(); i++) {
      char c = pattern.charAt(i);
      if (c == '*') regex.append(".*");
      else if (c == '?') regex.append('.');
      else regex.append(Pattern.quote(String.valueOf(c)));
    }
    return Pattern.matches(regex.toString(), value);
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

  private static void validateClassSelector(String selector, Style style) {
    if (selector.isEmpty()) {
      throw invalid("class selector must not be empty");
    }
    boolean hasGlob = selector.indexOf('*') >= 0 || selector.indexOf('?') >= 0;
    if (!hasGlob) {
      if (style == Style.INTERNAL) validateInternalName(selector);
      else if (style == Style.BINARY) validateBinaryName(selector);
      else validateFullyQualifiedName(selector, "class selector");
      return;
    }

    int segmentStart = 0;
    char separator = style == Style.INTERNAL ? '/' : '.';
    for (int index = 0; index <= selector.length(); index++) {
      if (index == selector.length() || selector.charAt(index) == separator) {
        if (index == segmentStart) {
          throw invalid("class selector must use non-empty name components");
        }
        validateGlobIdentifier(selector.substring(segmentStart, index), "class selector");
        segmentStart = index + 1;
      }
    }
  }

  private static void validateInternalName(String selector) {
    if (selector.startsWith("/") || selector.endsWith("/"))
      throw invalid("internal class selector has an empty component");
    for (String component : selector.split("/", -1)) {
      if (component.isEmpty()) throw invalid("internal class selector has an empty component");
      validateGlobIdentifier(component, "class selector");
    }
  }

  private static void validateBinaryName(String selector) {
    if (selector.startsWith(".") || selector.endsWith(".")) {
      throw invalid("binary class selector has an empty component");
    }
    for (String component : selector.split("\\.", -1)) {
      if (component.isEmpty()) throw invalid("binary class selector has an empty component");
      validateGlobIdentifier(component, "class selector");
    }
  }

  private static void validateMethodDescriptor(String descriptor) {
    if (descriptor.isEmpty() || descriptor.charAt(0) != '(') {
      throw new IllegalArgumentException("invalid method descriptor");
    }
    int index = 1;
    while (index < descriptor.length() && descriptor.charAt(index) != ')') {
      index = descriptorTypeEnd(descriptor, index, false);
    }
    if (index >= descriptor.length() || descriptor.charAt(index) != ')') {
      throw new IllegalArgumentException("missing descriptor close parenthesis");
    }
    index = descriptorTypeEnd(descriptor, index + 1, true);
    if (index != descriptor.length()) {
      throw new IllegalArgumentException("trailing descriptor characters");
    }
  }

  private static int descriptorTypeEnd(String descriptor, int start, boolean allowVoid) {
    if (start >= descriptor.length()) throw new IllegalArgumentException("missing descriptor type");
    int index = start;
    while (index < descriptor.length() && descriptor.charAt(index) == '[') {
      if (index - start == 255) throw new IllegalArgumentException("array descriptor too deep");
      index++;
    }
    if (index >= descriptor.length()) throw new IllegalArgumentException("missing array type");
    char type = descriptor.charAt(index);
    if ("ZBCSIJFD".indexOf(type) >= 0) return index + 1;
    if (type == 'V' && allowVoid && index == start) return index + 1;
    if (type != 'L') throw new IllegalArgumentException("invalid descriptor type");
    int end = descriptor.indexOf(';', index + 1);
    if (end < 0 || end == index + 1)
      throw new IllegalArgumentException("invalid object descriptor");
    String name = descriptor.substring(index + 1, end);
    if (name.startsWith("/")
        || name.endsWith("/")
        || name.contains("//")
        || name.indexOf('.') >= 0
        || name.indexOf('[') >= 0
        || name.indexOf('(') >= 0
        || name.indexOf(')') >= 0) {
      throw new IllegalArgumentException("invalid internal class name in descriptor");
    }
    return end + 1;
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
