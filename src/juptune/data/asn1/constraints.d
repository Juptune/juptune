/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.asn1.constraints;

import juptune.core.util : Result;

enum Asn1ConstraintError
{
    none,

    permittedAlphabetCharNotAllowed,
}

// TODO: This is on hold, but I wanted to keep this function around as reference.

/++
 + Implements ASN.1's Permitted Alphabet constraint. This constraint
 + enforces that each character within the given string is allowed within a specific alphabet.
 +
 + Notes:
 +  Use `juptune.data.alphabet` for implementations of `AlphabetT`.
 +
 +  `CharT` can be anything supported by `AlphabetT`.
 +
 +  If you pass in `createErrorString`, then this function will allocate memory to provide
 +  a more precise error message.
 +
 + Params:
 +  toCheck             = The string to check.
 +  alphabet            = The alphabet to compare the input string against.
 +  createErrorString   = Controls whether extra context is generated within any error messages generated.
 +
 + Throws:
 +  `Asn1ConstraintError.permittedAlphabetCharNotAllowed` if the check fails.
 +
 + Returns:
 +  A `Result` indicating whether the constraint passed or not.
 + ++/
Result asn1ConstraintPermittedAlphabet(AlphabetT, CharT)(
    scope const(CharT)[] toCheck,
    scope auto ref AlphabetT alphabet,
    bool createErrorString = false, // Reminder: D has named parameters now! Use them for clarity instead of Flags!
)
{
    import juptune.core.ds   : Array, String2;
    import juptune.core.util : toStringSink;

    Array!char error;
    bool wasError;

    size_t cursor;
    while(cursor < toCheck.length)
    {
        const oldCursor = cursor;
        const ch = alphabet.next(toCheck, cursor);
        if(!alphabet.isAllowed(ch))
        {
            wasError = true;
            if(!createErrorString)
                continue;

            if(error.length == 0)
            {
                error.reserve(256);
                error.put("Failing chars: ");
            }

            error.put(ch);
            error.put("(@ ");
            toStringSink(oldCursor, error);
            error.put("->");
            toStringSink(cursor, error);
            error.put("), ");
        }
    }

    return wasError 
        ? Result.make(
            Asn1ConstraintError.permittedAlphabetCharNotAllowed, 
            "At least one character within the string is not allowed with the given alphabet.",
            String2.fromDestroyingArray(error),
        ) 
        : Result.noError;
}
///
@("Permitted Alphabet")
unittest
{
    import juptune.core.util     : resultAssert;
    import juptune.data.alphabet : AsciiAlphabet;

    auto lowerCaseOnly = AsciiAlphabet!"abcdefghijklmnopqrstuvwxyz"();

    asn1ConstraintPermittedAlphabet("bazinga", lowerCaseOnly, createErrorString: true).resultAssert;
    assert(asn1ConstraintPermittedAlphabet("BAZINGA", lowerCaseOnly, createErrorString: true).isError);
}