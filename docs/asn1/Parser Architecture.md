# Overview

This file serves to provide a decently in-depth view into how Juptune's support for the ASN.1 notation is structured.

Please note, this is only for the support for ASN.1 **notation** (`juptune.asn1.lang`) and not for the binary encoding support, as that code is relatively straightforward.

## File structure

The files under the `src/juptune/data/asn1/lang/` directory are as follows:

* `ast.d` - Contains the syntax analysis models.
* `ast2ir.d` - Functions for converting `ast.d` models into `ir.d` models, while performing like semantics analysis.
* `common.d` - Some common functionality, mainly around managing allocations.
* `ir.d` - Contains the semantics analysis models. This is the main model used for things like codegen as well.
* `lexer.d` - Contains the lexer, for lexical analysis.
* `parser.d` - Consumes tokens from the lexer, and creates `ast.d` models. In other words, performs syntax analysis.
* `typecheck.d` - A built-in visitor that implements the vast majority of semantics analysis, such as type checking.

## Flow

Juptune's ASN.1 parser uses a very standard flow of:

```mermaid
flowchart LR
    Lexer --> Syntax --> Semantics
```

Which in more specific terms looks like this:

1. Define an `Asn1ParserContext` (from `common.d`).
2. Create an `Asn1Lexer` with the ASN.1 notation to parse (from `lexer.d`).
3. Create an `Asn1Parser` with the previously created lexer (from `parser.d`).
4. Call `myParser.ModuleDefinition` to generate an `Asn1ModuleDefinitionNode` (from `ast.d`).
5. Call `asn1AstToIr` (from `ast2ir.d`), passing in the module definition so it can generate an `Asn1ModuleIr` (from `ir.d`).
6. Call `.doSemanticStage` on the module IR for any desired semantic passes.
7. Create an `Asn1TypeCheckVisitor` and allow it to visit the module IR (from `typecheck.d`), TODO: explain how to handle errors.
8. The `ir.d` models are now fully resolved and validated, and can be used for whatever purpose. This is where Juptune's support for ASN.1 notation ends.

## Lexer

The lexer has a very standard recursive top-down design, with only a couple of interesting points:

* Since some tokens require special parsing (e.g. numeric tokens), the lexer will stuff the specially parsed information into an `InnerValue` field, so that the parser doesn't have to do any extra work later.
* Currently, location information is stored soley in character indexes, so line numbers and the like have to be calculated outside of the lexer.
* Using the power of D, some aspects of the implementation (such as operator parsing, and even unittests!) are controlled via static, immutable constants found within the `Asn1Token` struct.
* The lexer has limited support for low-overhead lookaheads, but I never really needed it too much, so it's relatively underutilised within the parser.
* It doesn't attempt to perform error correction, so if a single error is encountered then the entire lexing operation stops dead in its tracks.

Beyond that, it's basically the same bog-standard lexer you've likely seen a million times before.

## AST

I made many, _many_ attempts at automatically generating both the AST and the parser and every single one ended badly. So I bit the bullet and implement both by hand.

My main goal with the AST was to make it easy for me to generate a 1:1 match with the grammar provided by the x.680 spec. Since the grammar was pretty simple, I opted towards leveraging D's `mixin template` feature to achieve this goal.

This allowed almost every AST node to be declaratively defined in a way that (mostly) matches the specs grammar.

All AST nodes also define a well-defined type (stored as an `enum`), however this never really turned out to be useful, and I'm not even sure it's actually used anywhere, so there's a lot of nodes that just use `FAILSAFE` as their type. You're free to completely ignore that part of `ast.d`.

### Types of grammar productions

Generally speaking there are 5 different types of distinct patterns used to define "productions" within the spec's grammar.

The first one are what I call "token" patterns, where the spec matches against a specific type of token without any other regard to its actual contents. For example, a number:

```d
/* Grammar:
    number
*/

final class Asn1NumberTokenNode : Asn1BaseNode
{
    // Matches against any number token
    mixin Token!(Asn1Token.Type.number, Asn1NodeType.tNumber);
}
```

The second one is what I call "static" patterns, where the spec matches against a very specific keyword that we have to preserve as it contains meaningful information. This is actually implemented as a templated class rather than a mixin template:

```d
/* Grammar:
    BooleanType ::= BOOLEAN
*/
// Asn1StaticNode basically just stores any token you give it, and provides no further functionality.
alias Asn1BooleanTypeNode = Asn1StaticNode!(Asn1NodeType.BooleanType);
```

The third one is what I call "Container" patterns, where a single grammar production contains multiple different lexer tokens. Some grammar productions only contain one other production, in which case I still also use `Container` since it keeps things simple:

```d
/* Grammar:
    DefinitiveNameAndNumberForm ::= identifier "(" DefinitiveNumberForm ")"
*/
final class Asn1DefinitiveNameAndNumberFormNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.DefinitiveNameAndNumberForm,
        Asn1IdentifierTokenNode,
        Asn1DefinitiveNumberFormNode,
    );
}

/* Grammar:
    DefinitiveNumberForm ::= number
*/
final class Asn1DefinitiveNumberFormNode : Asn1BaseNode
{
    mixin Container!(Asn1NodeType.DefinitiveNumberForm, Asn1NumberTokenNode);
}

// Notable function examples:
myNameAndNumberForm.getNode!Asn1DefinitiveNumberFormNode() // Gets the Asn1DefinitiveNumberFormNode stored within the Asn1DefinitiveNameAndNumberFormNode
```

The fourth one is what I call "OneOf" patterns, which are simply just a list of alternative grammar productions that can be used as a single production. For example, negative numbers are defined as part of the grammar via this mechanism:

```d
/* Grammar:
    SignedNumber ::=
        number
        | "-" number
*/

// This also shows the usage of nested classes for bespoke productions that aren't given a unique name in the grammar.
final class Asn1SignedNumberNode : Asn1BaseNode
{
    final static class Negative : Asn1BaseNode
    {
        mixin Container!(Asn1NodeType.FAILSAFE,
            Asn1NumberTokenNode,
        );
    }

    // The parser will figure out whether to use the `Negative` variant or a normal `Asn1NumberTokenNode` instead.
    //
    // While we don't store the `-` token anywhere, we instead use the type system to encode the alternative production.
    mixin OneOf!(Asn1NodeType.SignedNumber,
        Asn1NumberTokenNode,
        Negative,
    );
}

// Notable function examples:
signedNumber.isNode!(Asn1SignedNumberNode.Negative) // Checks whether the number is negative.
signedNumber.asNode!Asn1NumberTokeNode // Gets the number as its non-negative case (or crashes the program if the negative case is being stored).
signedNumber.match( // Exhaustively match every possible case
    (Asn1NumberTokenNode) => ...,
    (Asn1SignedNumberNode.Negative) => ...
)
```

The final one is what I call `List` productions, which as the name suggests, contains a list of some other grammar production:

```d
/* Grammar:
    SymbolsFromModuleList ::=
        SymbolsFromModule
        | SymbolsFromModuleList SymbolsFromModule
*/
final class Asn1SymbolsFromModuleListNode : Asn1BaseNode
{
    mixin List!(Asn1NodeType.SymbolsFromModuleList, Asn1SymbolsFromModuleNode);
}
```

## Syntax Parser

Honestly, `parser.d` is my least favourite code in the entirety of Juptune so far. It it **easily** the most boring, tedious thing I have ever written.

Regardless, it's a relatively standard implementation of a hand written parser: look at the next token or two; branch depending on what the grammar says should exist in the given position.

In order to reduce mental load and make debugging less of a stack chasing hellscape, I've attempted to only split parsing code into separate functions if:

1. It makes the code cleaner overall or for some other organisational purpose.
2. A specific grammar production is used in several places, hence needing to be a function.

The code in `parser.d` also follows a very different style of formatting that prioritises keeping each line within the file impactful. This is because most of the code is extremely similar so being able to understand singular lines is less important than understanding the entire flow of the code... if that makes any sense.

The parser does not attempt any sort of error correction, so will immediately stop itself on the first error encountered.

### Token consumption

The 3 main basic parts of the parser are:

```d
Result peek(scope out Asn1Token token);
Result consume(scope out Asn1Token token);
Result consume() @nogc nothrow; // Consume the token without capturing it into a variable.
```

The parser completely skips over whitespace and comment tokens, as such the AST does not preserve how the user formatted their code, nor the comments they wrote (which I _should_ bother to preserve at some point though).

Honestly my main suggestion is to just get stuck into the code - it's not super hard to reason about, and doesn't rely on anything fancy.

If there's any questions around it that you'd like clarification or answers for (e.g. around backtracking), please let me know and I'll be glad to update the docs here with more information.

## ast2ir

While the AST doesn't fully preserve all information about how the original input is formatted, it still preserves a _lot_ of that information due to its close to 1:1 reflection of the ASN.1 grammar.

The AST nodes are also completely unsuitable for any complex purpose, as they lack any additional metadata or fields. It's for this reason that the IR nodes exists, and why `ast2ir.d` exists to perform the translation.

The `asnAstToIr` functions will take the complex, deeply nested AST structure and place it into the more simplified yet flexible IR structure, while also performing a light amount of semantics checks.

As with the syntax parser, it's better to just get stuck into the code since it's not very complex, and is likely the easier part of the entire implementation to read outside of the lexer's code.

The converter functions usually won't end the process the moment an error is encountered, but instead will pass any errors into the provided error handler. The error handler can do anything the user desires, such as printing to stderr or whatever.

## Asn1BaseIr.doSemanticStage

Ideally the IR would be a fully immutable structure, and all semantic passes could be performed via code that's external to `ir.d`.

However there's a few parts of semantics analysis that requires mutation of the IR structure (e.g. resolving references requires internal node mutations), so the `doSemanticStage` function exists on each IR node to perform these specific passes.

This function takes an `Asn1BaseIr.SemanticStageBit` which describes the specific pass it should perform. IR nodes will propagate this to any of their child nodes automatically, so most of the time the user code only needs to perform this call on the main `Asn1ModuleIr` node.

### SemanticStageBit.resolveReferences

This stage largely revolves around letting `Asn1TypeReferenceIr` and `Asn1ValueReferenceIr` instances resolve their underlying type/value.

This is performed by propagating a `lookup` function throughout the entire IR tree, which is often wrapped by specific nodes so that identifiers can be resolved to a specific IR node.

This usually allows a parent node to easily provide scoped access to its members so that a child node can access them during this pass.

It's a little annoying to wrap your head around, but again, give the code a look over and it shouldn't be _too_ mind boggling to deal with (until the bugs start rolling in).

### SemanticStageBit.implicitMutations

Some ASN.1 types/specific parts of the spec are only able to be performed later within the semantic stage (a lot of them especially rely on references being resolved), and so this is where this particular stage comes into play.

I'll try to update this area once the implementation is more spec-compliant, as there's still a load of unimplemented parts, but this essentially covers things such as:

* Providing values to un-valued named bits/named numbers/whatever.
* Setting whether a tag is EXPLICIT or IMPLICIT depending on whatever the `TagDefault` is.
* The entire madness around AUTOMATIC tags.
* And a bunch more stuff...

Essentially any mutation that's implicit to a specific type, or implicit to how ASN.1 notation works as a whole, is covered here.

## Type Checker

Despite being called the "type checker", this part of the code is actually responsible for all remaning parts of the semantics analysis, which roughly includes:

* Ensuring all ValueAssignments pass their type checks.
* Ensuring all constraints have value types that make sense for the given constrained type.
* Ensuring all constraints are valid and upheld.
* Probably more...

Since these checks don't require mutation of the IR nodes, this is implemented as a simple visitor within `typecheck.d`.

There's a bit of complexity around how constraints are handled, but I feel the code is _relatively_ easy to get your head around, even if it's not pretty to look at.

At the time of writing this (May 2025) there's a *lot* still left unimplemented here, partly due to lack of time and motivation, and partly due to the fact ASN.1 is insanely overengineered; complex in ways you wouldn't expect, and very, very difficult to implement to-spec.

## dasn1

dasn1 is a tool bundled into this repo that makes use of Juptune's ASN.1 support.

Right now it's a completely barebones prototype with 0 useful functionality, but ideally it'll be a tool that can perform the following actions:

1. Validate any given ASN.1 notation (i.e. passes all semantics checks).
2. Provides the ability to generate D code from an ASN.1 module, as well as generate decoding functions for the models.
3. Some other useful debug related functions such as dumping the AST/IR models.
4. _Maybe_ it could be fun if it could decode an arbitrary ASN.1 encoding into a human friendly format, especially if it's given an associated ASN.1 module. But I'd likely do that solely for fun rather than anything else, so don't ever expect this to happen :D

Once dasn1 is actually useful I may update this area a bit more, mainly to detail how it uses Juptune's IR.