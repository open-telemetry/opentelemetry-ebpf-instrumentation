# Java dynamic method references

← [Config v2 dynamic instrumentation](dynamic-instrumentation.md)

This document defines the proposed Java interpretation of a function target in
Config v2 dynamic span declarations. The reference format is inspired by the
`Class#method(parameterTypes)` form used by Java documentation tools and IDE
Copy Reference actions. For example:

```yaml
on:
  function: "io.opentelemetry.contrib.dynamic.policy.PolicyProviderConfig#create"
```

The Java runtime supports this selector for named method spans on explicitly
selected Java processes. It resolves loaded classes and methods according to
the rules below, reevaluating matching classes as they load and unload. The
converter rejects unsupported Java targets and attribute capture; support for
those remains a separate runtime change.

## Syntax

A Java method reference has this grammar:

```text
method-reference       = class-selector, "#", method-selector, [ "(", [ parameter-list ], ")" ] ;
class-selector         = qualified-name | class-name-glob ;
class-name-glob        = class-glob-character, { class-glob-character } ;
class-glob-character   = java-identifier-character | "." | "*" | "?" ;
method-selector       = java-identifier | method-name-glob ;
method-name-glob       = method-glob-character, { method-glob-character } ;
method-glob-character  = java-identifier-character | "*" | "?" ;
parameter-list         = parameter-type, { ",", parameter-type } ;
parameter-type         = java-type-name, { "[]" } ;
java-type-name         = primitive-type | qualified-name ;
qualified-name         = java-identifier, { ".", java-identifier } ;
```

`class-selector` is either the fully qualified Java name of one class or a glob
pattern over fully qualified class names. A class selector without `*` or `?`
remains an exact class name and selects one target name. A class-name glob
intentionally expands to the distinct matching fully qualified class names.
There is no separate package selector: package matching is just a class-name
pattern. Since `*` also matches dots, a pattern such as `com.example.*` can
match classes in nested packages. Nested classes and types use dot-separated
canonical names.

`method-selector` is either one Java identifier or a glob pattern containing
`*` or `?`; without either wildcard it is an exact method name. OBI already
uses glob matching for attribute filters and service selection; this contract
applies the same basic syntax to both selector components. `*` matches zero or
more characters, including dots in a class name, and `?` matches exactly one
character, including a dot in a class name. Other characters are literal; this
contract does not define character classes, alternation, or escaping. Class-name glob operators are
scoped to the fully qualified class-name component, and method-name glob
operators to the method-name component. The parameter list remains exact, and
whitespace is not allowed within the reference. The whole reference should be
quoted in YAML.

For example, `com.example.Repository#find*(java.lang.String)` matches methods
whose names start with `find` and whose erased parameter list is exactly
`java.lang.String`. `com.example.*Repository#find*(java.lang.String)` uses a
class-name pattern to match distinct FQCNs ending in `Repository` and a
method-name pattern to select all matching methods in each target class. Globs
intentionally select sets: multiple matched methods are not ambiguous, and a
class-name glob expands to distinct FQCNs rather than classloader copies.

The parameter list is optional:

- Without a parameter list, the reference considers every eligible method
  whose name matches the selector on the named class. An exact method name
  resolves only when exactly one method matches; a glob selects every matching
  method.
- With a parameter list, each entry is a fully qualified reference type or a
  Java primitive type. Array dimensions use `[]`; varargs are written as the
  equivalent array type. For example, `java.lang.String,int[]`.
- `java-identifier` and `primitive-type` use Java identifier and primitive
  type names, respectively. The accepted primitive types are `boolean`,
  `byte`, `short`, `int`, `long`, `char`, `float`, and `double`; `void` is not
  a parameter type. Simple reference names such as `String` are not accepted;
  use `java.lang.String`.
- Generic types use their erased JVM parameter types. Type arguments, Java
  wildcard type syntax, and parameter names are not part of the parameter list.
- An empty list, `()`, selects a zero-argument method.

The return type is not part of the selector. The reference does not perform
Java source overload resolution: it does not apply boxing, primitive widening,
assignability, or varargs invocation conversions. Parameter types must match
the method's erased parameter types exactly.

## Resolution contract

Resolution is scoped to the target JVM and evaluated independently for each
target fully qualified class name (FQCN):

1. An exact class selector defines one target FQCN. A class-name glob expands
   to the set of distinct loaded FQCNs matching the pattern.
2. For each target FQCN, find loaded class definitions with that exact name.
   If more than one classloader defines the same FQCN, that target is
   **ambiguous** and none of its copies are selected. This ambiguity does not
   prevent other, distinct FQCNs from resolving.
3. Within one class definition, find non-synthetic methods declared by that
   class whose name matches `method-selector` and, when supplied, whose erased
   parameter types match the reference. Synthetic methods, including
   compiler-generated bridge methods, are excluded before counting matches.
   A method inherited from a superclass or interface is not considered
   declared by the named class; reference its declaring class instead. Static
   and instance methods are both eligible.
4. With one class definition, no eligible method is **unresolved**. An exact
   method name with one eligible method is **resolved**; with more than one it
   is **ambiguous**. A method-name glob with one or more eligible methods is
   **resolved** to the set of all matches, even when that set contains
   multiple methods.

Resolution is reevaluated as matching classes are loaded and unloaded; it is
not a one-time snapshot. A class-name glob that currently matches no loaded
FQCNs is **pending** and selects nothing. For every target FQCN, resolve its
loaded class definitions and eligible methods independently:

- No loaded class definition for a target FQCN is **pending**. It may resolve
  when that class is loaded.
- Multiple classloader definitions of the same target FQCN are **ambiguous**;
  none of those copies are selected. This affects only that target FQCN.
- With one class definition, no eligible method is **unresolved** and reports
  a resolution error. A loaded class with no method match is not pending.
- With one class definition, an exact method name is **resolved** when exactly
  one eligible method matches, and **ambiguous** when more than one matches.
  A method-name glob is **resolved** when one or more eligible methods match;
  the selected set includes every match. Multiple glob matches are
  intentional, not ambiguous.

The selected method or methods are identified by their declaring class
definition, including its defining classloader. A class-name glob expands to
distinct FQCNs, not to classloader copies. An unresolved or ambiguous outcome
for one target reports that target's resolution error without preventing other
FQCNs from applying valid methods. This also applies to exact-method overload
ambiguity for one target in a class-name glob.

On each relevant class load or unload, recompute the set of loaded FQCNs
matching a class-name glob and reevaluate each target independently. An exact
class selector continues to name its single FQCN as it loads and unloads.
When an FQCN leaves a glob's set, detach all methods selected for it; when an
FQCN enters, resolve it. For any target, pending, unresolved, or ambiguous
states detach active selections. When a target becomes resolved, attach its
exact method or every method in its glob result. If a resolved glob's method
set changes,
detach removed methods and attach newly matching methods. A duplicate
classloader definition makes only its FQCN ambiguous; unloading the duplicate
can restore that target to resolved, unresolved, or pending. Unloading the
last definition of a target makes it pending. These per-target outcomes do
not suppress valid selections for other FQCNs matched by the same pattern.

Constructors are not currently supported. Their `this()`/`super()` delegation
must run before the instance is initialized, and Byte Buddy throwable advice
cannot cover that delegation. Full constructor-span semantics need a separate
design for initialization and failure handling; this is not a permanent
limitation of dynamic spans. Return-type selection and matching inherited
methods through a subtype require a future contract change rather than implicit
fallback behavior.

## Java runtime support

Java accepts `on.function` references using this syntax when the capture rule
explicitly matches `process.language_glob: [java]`. Class and method `*` and
`?` globs are supported. A selected method emits one completed span through
the existing custom-span event transport; returned values and arguments are
not captured. `attributes`, `automatic_attributes`, `function_noret`, and USDT
targets remain rejected by the runtime converter.
