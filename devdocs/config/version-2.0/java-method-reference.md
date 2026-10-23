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

This is a selector contract, not a promise of runtime support. The Config v2
converter continues to reject non-empty dynamic span declarations until Java
instrumentation is implemented.

## Syntax

A Java method reference has this grammar:

```text
method-reference = class-name, "#", method-name, [ "(", [ parameter-list ], ")" ] ;
method-name    = java-identifier | method-name-glob ;
method-name-glob = glob-character, { glob-character } ;
glob-character = java-identifier-character | "*" | "?" ;
parameter-list   = parameter-type, { ",", parameter-type } ;
parameter-type   = java-type-name, { "[]" } ;
java-type-name   = primitive-type | qualified-name ;
qualified-name   = java-identifier, { ".", java-identifier } ;
```

`class-name` is the fully qualified Java name of one class. It is an exact
class name, not a package, glob, regular expression, or subtype selector.
Nested classes and types use dot-separated canonical names. `method-name` is
either one Java identifier or a glob pattern containing `*` or `?`; a selector
without either wildcard is an exact method name. OBI
already uses glob matching for attribute filters and service selection; this
contract applies the same basic syntax to method names. `*` matches zero or
more characters and `?` matches exactly one character. Other characters in the
method name are literal; this contract does not define character classes,
alternation, or escaping. Glob operators are scoped to the method-name
component only. The parameter list remains exact, and whitespace is not
allowed within the reference. The whole reference should be quoted in YAML.

For example, `com.example.Repository#find*(java.lang.String)` matches methods
whose names start with `find` and whose erased parameter list is exactly
`java.lang.String`. Globs intentionally select a set of methods, so multiple
matching methods are not ambiguous. The exact class name still identifies one
class; a method-name glob does not match subclasses or classloader copies.

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
- Generic types use their erased JVM parameter types. Type arguments, wildcard
  syntax, and parameter names are not part of the reference.
- An empty list, `()`, selects a zero-argument method.

The return type is not part of the selector. The reference does not perform
Java source overload resolution: it does not apply boxing, primitive widening,
assignability, or varargs invocation conversions. Parameter types must match
the method's erased parameter types exactly.

## Resolution contract

Resolution is exact and scoped to the target JVM:

1. Find classes whose fully qualified name exactly equals `class-name`.
2. Within each matching class, find non-synthetic methods declared by that
   class whose name matches `method-name` and, when supplied, whose erased
   parameter types match the reference. Synthetic methods, including
   compiler-generated bridge methods, are excluded before counting matches.
   A method inherited from a superclass or interface is not considered
   declared by the named class; reference its declaring class instead. Static
   and instance methods are both eligible.
3. Multiple definitions of the named class in different classloaders are
   ambiguous, regardless of the methods each definition declares. With one
   matching class definition, no eligible methods is unresolved. An exact
   method name with one eligible method is resolved; with more than one it is
   ambiguous. A method-name glob with one or more eligible methods is resolved
   to the set of all matches, even when that set contains multiple methods.

Resolution follows matching class definitions as they are loaded and unloaded
in the target JVM; it is not a one-time snapshot. The states are:

- No matching class definition is **pending**. It selects nothing and may
  resolve when the class is loaded.
- Matching definitions of the named class in multiple classloaders are
  **ambiguous**, regardless of whether each definition declares an eligible
  method.
- With one matching class definition, no eligible method is **unresolved**.
  This is a resolution error, not a pending state; loading the class does not
  silently defer a misspelled or otherwise absent method.
- With one matching class definition, an exact method name is **resolved**
  when exactly one eligible method matches, and **ambiguous** when more than
  one matches. A method-name glob is **resolved** when at least one eligible
  method matches; the selected set includes every matching method. Multiple
  glob matches are intentional, not ambiguous. Each selected method is
  identified by its declaring class definition, including its defining
  classloader.

Resolution is reevaluated after each relevant class load or unload. If the new
state is pending, unresolved, or ambiguous, any active selection must be
detached. When a glob remains resolved but its matching set changes, removed
methods must be detached and newly matching methods attached; all current
matches stay selected. Whenever reevaluation yields resolved, the runtime must
attach the exact method or every method in the glob result; this is how pending,
unresolved, or ambiguous references recover. A resolved exact selector that
changes to a different class definition or method must detach the previous
selection and attach the new one. A pending reference can resolve when a
matching class definition appears and the selector has a resolved result. An
unresolved reference remains an error while its matching class is loaded, but
becomes pending if that class is unloaded. An ambiguous reference can recover
to resolved, unresolved, or pending when unloading leaves a unique matching
class with eligible matches, a unique matching class without an eligible
method, or no matching classes, respectively. A future Java runtime
implementation should report these outcomes distinctly.

Unresolved and ambiguous declarations must report their own resolution error
and must not prevent valid sibling declarations under the same capture rule
from applying. Pending declarations are not errors while waiting for a
matching class to load.

Constructors are not supported by this method-reference form. Return-type
selection and matching inherited methods through a subtype require a future
contract change rather than implicit fallback behavior.
