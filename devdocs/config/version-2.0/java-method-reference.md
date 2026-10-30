# Java dynamic method references

← [Config v2 dynamic instrumentation](dynamic-instrumentation.md)

This document proposes the Java interpretation of a function target in Config
v2 dynamic span declarations. This is a design proposal; the current
implementation does not yet support all behavior described here. Matching is
best-effort: instrument every valid match, and do not let an unmatched target
prevent valid sibling matches.

```yaml
on:
  function: "io/opentelemetry/contrib/dynamic/policy/PolicyProviderConfig.create"
```

HotSpot references use an internal class name followed by `.` or a binary class
name followed by `::` and a method name: `java/lang/String.indexOf` or
`java.lang.String::indexOf` ([HotSpot method patterns](https://docs.oracle.com/en/java/javase/15/vm/writing-directives.html)).
These names match the exact internal or binary spelling; they do not fall back
to canonical nested names. An optional full JVM descriptor is exact, including its return type, e.g.
`java/lang/String.indexOf(I)I`; see [JVMS §4.3.3](https://docs.oracle.com/javase/specs/jvms/se15/html/jvms-4.html#jvms-4.3.3).
The proposal also accepts parameter-only forms such as `(I)` as an extension;
they omit the return constraint and are not complete JVM descriptors.

HotSpot's dotted class form uses binary nested names such as
`java.lang.Outer$Inner::accept`.

As a Java source-tooling convenience, the IntelliJ/Javadoc form
`com.example.Outer.Inner#accept(java.lang.String)` is also accepted. Its
parameter types use Java source names and its return type is unspecified.
For `#` selectors, canonical and binary nested-type spellings are accepted for
class and parameter names. Canonical spellings resolve against type metadata;
when a package/class interpretation and a nested-class interpretation both
exist, both may match. This alias behavior does not apply to HotSpot selectors.
HotSpot class and descriptor parameter names require exact internal or binary
spellings. The `$` character is literal in patterns.

## Syntax and validation

This Java PR removes the requirement for `process.language_glob: [java]`; this
is not deferred to a separate follow-up. The language filter remains optional
and, when set, narrows process selection. The current implementation still
requires it until this PR's change is implemented.
The shared configuration layer validates function-target structure and the
optional filter, but does not parse Java method syntax. The Java runtime parses
Java selectors for Java processes. The current implementation still accepts
only `Class#method` references.

The table compares proposed selector formats; it does not claim every form is
currently implemented or emitted by the named tools. Assume `Runner` declares
void `run()`, `run(int)`, `run(int[])`, `accept(String[])`, and
`accept(List<String>)`; generic `consume<T extends Number>(T)`; `Outer.Inner`
is nested; and a separate top-level `Inner` exists in package
`com.example.Outer`. Assume `StringValue` implements `Supplier<String>` with
`String get()`, which has the compiler bridge `Object get()`. A compiled
anonymous class in `Outer` has the hypothetical binary name `Outer$1`; such
generated names are not stable guarantees.

| Use case | HotSpot internal `/` + `.` | HotSpot dotted binary `::` | IntelliJ/Javadoc-style `#` | Outcome / comment |
|---|---|---|---|---|
| C1: All `run` overloads | `com/example/Runner.run` | `com.example.Runner::run` | `com.example.Runner#run` | Omitting parameters selects all eligible overloads. |
| C2: Exact `run(int)` returning `void` | `com/example/Runner.run(I)V` (full descriptor requires `void`) | `com.example.Runner::run(I)V` (full descriptor requires `void`) | `com.example.Runner#run(int)` (return unspecified) | — |
| C3: `run(int)`, return unspecified | `com/example/Runner.run(I)` (proposed parameter-only extension; any return, bridge skipped; not a full descriptor) | `com.example.Runner::run(I)` (proposed parameter-only extension; any return, bridge skipped; not a full descriptor) | `com.example.Runner#run(int)` (return unspecified) | — |
| C4: Nested: `package com.example; class Outer { class Inner { void run() {} } }` | `com/example/Outer$Inner.run` | `com.example.Outer$Inner::run` | `com.example.Outer.Inner#run` (also matches C5 if both types exist) | — |
| C5: Top-level: `package com.example.Outer; class Inner { void run() {} }` | `com/example/Outer/Inner.run` (selects only this target) | `com.example.Outer.Inner::run` (selects only this target) | `com.example.Outer.Inner#run` (also matches C4 if both types exist) | — |
| C6: Anonymous class method | `com/example/Outer$1.run` (`$` is literal; nesting is not inferred) | `com.example.Outer$1::run` (`$` is literal; nesting is not inferred) | `com.example.Outer$1#run` (accepted binary alias; no canonical name assumed) | — |
| C7: Broad `get` | `com/example/StringValue.get` (broad; bridge skipped) | `com.example.StringValue::get` (broad; bridge skipped) | `com.example.StringValue#get` (broad; bridge skipped) | Selects real `String get()`. |
| C8: Exact bridge `Object get()` | `com/example/StringValue.get()Ljava/lang/Object;` (exact full descriptor selects bridge) | `com.example.StringValue::get()Ljava/lang/Object;` (exact full descriptor selects bridge) | Not expressible by return type | — |
| C9: Array/varargs `accept(String[])` | `com/example/Runner.accept([Ljava/lang/String;)V` | `com.example.Runner::accept([Ljava/lang/String;)V` | `com.example.Runner#accept(java.lang.String[])` | Array and varargs parameters have the same erased array type; `accept*` can be used as a method glob. |
| C10: Generic `accept(List<String>)` | `com/example/Runner.accept(Ljava/util/List;)V` | `com.example.Runner::accept(Ljava/util/List;)V` | `com.example.Runner#accept(java.util.List)` | The type argument is erased; the selector cannot distinguish `List<String>` from `List<Integer>`. Such overloads cannot coexist in one class because they erase identically. |
| C11: Bounded `consume<T extends Number>(T)` | `com/example/Runner.consume(Ljava/lang/Number;)V` | `com.example.Runner::consume(Ljava/lang/Number;)V` | `com.example.Runner#consume(java.lang.Number)` | The parameter erases to its leftmost bound, `Number`, not always to `Object`. |
| C12: Duplicate classloaders | Same selector as C1 | Same selector as C1 | Same selector as C1 | All matching class definitions are selected independently; classloader filtering is not supported. |

The HotSpot examples follow [HotSpot method patterns](https://docs.oracle.com/en/java/javase/15/vm/writing-directives.html).
The `#` examples describe an accepted source-style convenience syntax; they
are not a claim that IntelliJ or Javadoc emits every spelling shown.
For `#` selectors, `com.example.Outer.Inner` can match either the top-level
class `com.example.Outer.Inner` or nested class `com.example.Outer$Inner`. If
both types resolve, both may match. HotSpot slash/internal and dotted/binary
selectors match only the spelling given; `$` is literal and does not infer
nested-type metadata.

`*` and `?` are supported in class and method names; other glob syntax is
undefined. Quote the complete value in YAML.

Without a parameter clause, all overloads with a matching name are selected.
In the source-style form, `()` selects zero parameters without constraining
the return type. The proposed parameter-only descriptor extension `()` has
the same parameter-only behavior; it is not a complete JVM descriptor. A full
JVM descriptor such as `()V` selects a zero-parameter void method, and all full
JVM descriptors include the return type. Source-style parameter
lists contain erased, fully qualified reference types or Java primitives;
arrays use `[]` and varargs use their array form (for example,
`com.example.Service#accept(java.lang.String[])` matches an array or varargs
parameter). No source overload conversions are applied. Generic arguments and
parameter names are not included.

Broad/name-only and parameter-only descriptor references exclude
compiler-generated bridge methods. An exact full JVM owner+name+descriptor
reference may select a bridge method. Other synthetic methods are not
blanket-excluded, subject to instrumentation support.

## Resolution contract

Resolution is best-effort within the target JVM. Each selector may produce
multiple valid class and method matches; instrument every matching class
definition independently, across all classloaders:

1. Match the class selector against loaded types. HotSpot internal and dotted
   forms require the exact internal or binary spelling. A `#` selector accepts
   canonical and binary names through type metadata; a canonical package/class
   spelling may resolve to both a top-level and nested type. Class globs expand
   to every loaded matching type name.
2. For each matched type name, consider every loaded class definition, including
   definitions from different classloaders. Do not reject duplicate
   classloader copies as ambiguous; each is an independent instrumentation
   target.
3. In each class definition, match declared methods by name and the optional
   parameter constraint. Source parameters and parameter-only descriptor
   extensions do not constrain return type. A full JVM descriptor matches
   parameters and return type exactly; a wrong return type is unresolved, not
   treated as a wildcard. Broad/name-only and parameter-only selectors skip
   bridge methods; an exact full JVM owner+name+descriptor may select one.
   Other synthetic methods are not blanket-excluded, subject to
   instrumentation support. Inherited methods are not considered declared by
   the named class; reference their declaring class instead. Static and
   instance methods are both eligible.
4. A class definition with matching methods is resolved to all matching
   methods. A loaded definition with no method match is unresolved and reports
   a target diagnostic. That diagnostic does not block valid method matches in
   other class definitions or sibling targets. Multiple overloads selected
   without a parameter constraint are intentional, not ambiguous.

Resolution is reevaluated as classes load and unload. A class selector or glob
with no loaded matching type is pending. When a type matches, resolve each of
its classloader definitions independently; when one definition unloads, detach
only its methods, leaving selections in other definitions intact. When a type
leaves a glob's set, detach its selected methods. Unloading the last matching
definition makes that target pending. Unresolved or pending targets do not
suppress valid matches for other definitions or targets.

The selected methods are identified by their declaring class definition,
including its defining classloader. No uniqueness check is performed across
classloaders. An exact return-type constraint remains exact even when other
methods with the same name and parameters exist.

Constructors are not currently supported. Their `this()`/`super()` delegation
must run before the instance is initialized, and Byte Buddy throwable advice
cannot cover that delegation. Full constructor-span semantics need a separate
design for initialization and failure handling; this is not a permanent
limitation of dynamic spans. Matching inherited methods through a subtype
requires a future contract change rather than implicit fallback behavior.

## Java runtime support

A selected method emits one completed span through the existing custom-span
event transport; returned values and arguments are not captured.
`attributes`, `automatic_attributes`, `function_noret`, and USDT targets are
outside this proposal.
