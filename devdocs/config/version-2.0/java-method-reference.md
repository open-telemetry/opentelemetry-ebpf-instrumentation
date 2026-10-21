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
2. Within the matching class, find methods declared by that class whose name
   and, when supplied, erased parameter types match the reference.
3. Resolve only when there is exactly one matching class definition and
   exactly one matching method. A method inherited from a superclass or
   interface is not considered declared by the named class; reference its
   declaring class instead. Static and instance methods are both eligible.

No matching class or method is **unresolved**. More than one matching method
is **ambiguous**. If the same class name is loaded by multiple classloaders in
the target JVM, the reference is also **ambiguous**; it does not implicitly
select every classloader copy. Neither unresolved nor ambiguous references
select a method. They are distinct outcomes and should be reported distinctly
by a future Java runtime implementation.

Each unresolved or ambiguous declaration must report its own resolution error
and must not prevent valid sibling declarations under the same capture rule
from applying. This contract does not define when a runtime retries resolution
for classes loaded after configuration.

Constructors are not supported by this method-reference form. Return-type
selection, matching inherited methods through a subtype, and selecting among
classloader copies require a future contract change rather than implicit
fallback behavior.
