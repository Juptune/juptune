module dasn1.builder;

final class StringBuilder
{
    import std.array : Appender;

    private
    {
        Appender!(char[]) _buffer;
        uint _indent;
        bool _isNewLine;
    }

    this()
    {
        this._isNewLine = true;
    }

    void indent()
    {
        this._indent++;
    }

    void dedent()
    in(this._indent != 0, "bug: indent level is already at 0, unbalanced indent/dedent calls?")
    {
        this._indent--;
    }

    void put(scope const(char)[] data)
    {
        import std.algorithm : splitter;

        foreach(line; data.splitter('\n'))
        {
            if(this._isNewLine)
            {
                foreach(i; 0..this._indent)
                    this._buffer.put("    ");
                this._isNewLine = false;
            }

            this._buffer.put(line);
            if(line.length != data.length) // Edge case: If the lengths are equal then there's no new line to put
            {
                this._buffer.put('\n');
                this._isNewLine = true;
            }
        }
    }

    void clear()
    {
        this._buffer.clear();
    }

    const(char)[] data() => this._buffer.data;
}