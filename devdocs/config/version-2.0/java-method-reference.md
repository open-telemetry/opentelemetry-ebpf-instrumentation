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
parameter-list   = parameter-type, { ",", parameter-type } ;
parameter-type   = java-type-name, { "[]" } ;
java-type-name   = primitive-type | qualified-name ;
qualified-name   = java-identifier, { ".", java-identifier } ;
```

`class-name` is the fully qualified Java name of one class. It is an exact
class name, not a package, glob, regular expression, or subtype selector.
Nested classes and types use dot-separated canonical names. `method-name` is
one Java identifier and must match the exact method name. Whitespace is not
allowed within the reference. The whole reference should be quoted in YAML.

Wildcard and glob selectors are not supported by this contract, and there is
no current plan to add them. A method reference is intended to identify one
method; a glob could select a broad, less predictable set of methods. A future
contract could define a separate selector form if selecting method sets is
needed.

The parameter list is optional:

- Without a parameter list, the reference considers every method with that
  name on the named class. It resolves only when exactly one method matches.
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
   class whose name and, when supplied, erased parameter types match the
   reference. Synthetic methods, including compiler-generated bridge methods,
   are excluded before counting matches.
3. Resolve only when there is exactly one matching class definition and
   exactly one matching method. A method inherited from a superclass or
   interface is not considered declared by the named class; reference its
   declaring class instead. Static and instance methods are both eligible.

Resolution follows matching class definitions as they are loaded and unloaded
in the target JVM; it is not a one-time snapshot. The states are:

- No matching class definition is **pending**. It selects nothing and may
  resolve when the class is loaded.
- A matching class definition with no eligible method is **unresolved**. This
  is a resolution error, not a pending state; loading the class does not
  silently defer a misspelled or otherwise absent method.
- Matching definitions of the named class in multiple classloaders are
  **ambiguous**, regardless of whether each definition declares an eligible
  method.
- Exactly one matching class definition with exactly one eligible method is
  **resolved** and selects that method. The selected method is identified by
  its declaring class definition, including its defining classloader.
- More than one eligible method on the unique matching class definition is
  **ambiguous** and selects nothing.

Resolution is reevaluated after each relevant class load or unload. If the new
state is not resolved, any active selection must be detached. If the new state
is resolved to a different class definition or method, the previous selection
must be detached and the new one attached. A pending reference can resolve
when a unique matching class and method appear. An unresolved reference remains
an error while its matching class is loaded, but becomes pending if that class
is unloaded. An ambiguous reference can recover to resolved, unresolved, or
pending when unloading leaves a unique matching class with one eligible
method, a unique matching class without an eligible method, or no matching
classes, respectively. A future Java runtime implementation should report
these outcomes distinctly.

Unresolved and ambiguous declarations must report their own resolution error
and must not prevent valid sibling declarations under the same capture rule
from applying. Pending declarations are not errors while waiting for a
matching class to load.

Constructors are not supported by this method-reference form. Return-type
selection and matching inherited methods through a subtype require a future
contract change rather than implicit fallback behavior.
