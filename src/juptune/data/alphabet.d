/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.alphabet;

/++
 + A simple alphabet provider that only allows a specific set of statically known
 + ascii characters.
 +
 + One tiny benefit of using a compile-time dataset is that `isAllowed` can actually get constant folded...
 + though you'd almost never use it on compile-time only data, but it's still cool!
 +
 + Params:
 +  AllowedChars_ = A string of Ascii characters, each of which will return true if passed to `isAllowed`.
 + ++/
struct AsciiAlphabet(string AllowedChars_)
{
    private static immutable _flags = (){
        ubyte[char.max / 8] flags;

        foreach(ch; AllowedChars_)
        {
            const byte_ = ch / 8;
            const bit   = ch % 8;
            flags[byte_] |= (1 << bit);
        }

        return flags;
    }();
    
    /// Forwarded template parameter.
    static immutable AllowedChars = AllowedChars_;

    bool isAllowed(char ch) @trusted @nogc nothrow pure const
    {
        const byte_ = ch / 8;
        const bit   = ch % 8;
        return (_flags[0..$].ptr[byte_] & (1 << bit)) != 0; // .ptr skips bounds checking
    }

    char next(scope const(char)[] str, scope ref size_t cursor) @safe @nogc nothrow pure
    {
        return str[cursor++];
    }
}
///
unittest
{
    auto alphabet = AsciiAlphabet!"az19"();
    assert(alphabet.isAllowed('a'));
    assert(alphabet.isAllowed('z'));
    assert(alphabet.isAllowed('1'));
    assert(alphabet.isAllowed('9'));

    assert(!alphabet.isAllowed(cast(char)0));
    assert(!alphabet.isAllowed(char.max));
    assert(!alphabet.isAllowed('b'));
    assert(!alphabet.isAllowed('2'));
}