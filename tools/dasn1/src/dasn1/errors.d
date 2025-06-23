/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dasn1.errors;

import juptune.data.asn1.lang : Asn1SemanticErrorHandler, Asn1Location;

final class DefaultErrorHandler : Asn1SemanticErrorHandler
{
    import core.stdc.stdio : printf;

    private
    {
        static struct Line
        {
            size_t start;
            size_t end;
        }

        string _debugName;
        Line[] _lines;
        uint   _indent;
        bool   _wasCalled;
    }

    this(string debugName, string sourceCode)
    {
        this._debugName = debugName;

        Line line;
        foreach(i, ch; sourceCode)
        {
            if(ch == '\n')
            {
                line.end = i;
                this._lines ~= line;
                line.start = line.end + 1;
                line.end = 0;
            }
        }
        line.end = sourceCode.length;
        this._lines ~= line;
    }

    @nogc nothrow:

    bool wasCalled() => this._wasCalled;

    override void startLine(Asn1Location location)
    {
        this._wasCalled = true;

        size_t lineIndex;
        foreach(i, line; this._lines)
        {
            if(line.start <= location.start && line.end >= location.start)
            {
                lineIndex = i;
                break;
            }
        }

        printf(
            "%.*s(line %lld char %lld): ",
            cast(uint)this._debugName.length,
            this._debugName.ptr,
            lineIndex + 1,
            location.start - this._lines[lineIndex].start,
        );
        foreach(i; 0..this._indent)
            printf("  ");
    }

    override void putInLine(scope const(char)[] slice)
    {
        printf("%.*s", cast(uint)slice.length, slice.ptr);
    }

    override void endLine()
    {
        printf("\n");
    }

    override void indent()
    {
        this._indent++;
    }

    override void dedent()
    in(this._indent != 0, "tried to dedent more than times than indent was called?")
    {
        this._indent--;
    }
}