module juptune.http.common;

import juptune.core.ds : Array, String;

private mixin template HttpMessageNoGCCommon()
{
    private
    {
        Array!ubyte      _body;
        Array!HttpHeader _headers;
    }

    @nogc nothrow:

    void putBody(scope const ubyte[] body) @trusted // TODO: Look into why Array.put isn't marked @trusted or @safe
    {
        this._body ~= body;
    }

    void setHeader(scope const char[] key, scope const char[] value) @trusted // ditto todo as putBody
    {
        // NOTE: We don't have an ordered map implementation, so for now
        //       we'll just use an array + a linear search.
        foreach(i, ref header; this._headers[])
        {
            if(header.name == key)
            {
                if(value.length == 0)
                    this._headers.remove(i);
                else
                    header._value = value;
                return;
            }
        }

        if(value.length != 0)
            this._headers ~= HttpHeader(key, value);
    }

    HttpHeader tryGetHeader(scope const char[] key, scope out bool wasFound) @safe
    {
        foreach(ref header; this._headers[])
        {
            if(header.name == key)
            {
                wasFound = true;
                return header;
            }
        }

        return HttpHeader("", "");
    }

    ref const(Array!HttpHeader) headers() scope return const @safe @nogc nothrow => this._headers;
    ref const(Array!ubyte) body() scope return const @safe @nogc nothrow => this._body;
}

struct HttpHeader
{
    private 
    {
        String _name;
        String _value;
    }

    this(NameT, ValueT)(scope NameT name, scope ValueT value) @trusted // @safe: The const removal is safe
    {
        import juptune.http.v1 : http1CanonicalHeaderNameInPlace;

        this._name = String(name);
        this._value = String(value);

        // Since the strings haven't ever escaped yet, it's safe to modify them in place.
        // NOTE: While it would be nice to check the validation result, this
        //       should get caught in the writer anyway. The annoyance of constructors :(
        scope nameSlice = cast(ubyte[])this._name[];
        scope valueSlice = cast(ubyte[])this._value[];
        http1CanonicalHeaderNameInPlace(nameSlice);
        http1CanonicalHeaderNameInPlace(valueSlice);
    }

    this(scope ref return typeof(this) src) @trusted @nogc nothrow // @safe: D can't figure out that the copy constructor... copies
    {
        this._name  = src._name;
        this._value = src._value;
    }

    ref const(String) name() scope return const @safe @nogc nothrow => this._name;
    ref const(String) value() scope return const @safe @nogc nothrow => this._value;
}

struct HttpRequest
{
    mixin HttpMessageNoGCCommon;

    private
    {
        String _method;
        String _path;
    }

    @nogc nothrow:

    this(scope ref return typeof(this) src) @trusted // @safe: D can't figure out that the copy constructor... copies
    {
        this._method  = src._method;
        this._path    = src._path;
        this._headers = src._headers;
        this._body    = src._body;
    }

    void withMethod(scope const char[] method) @safe
    {
        this._method = method;
    }

    void withPath(scope const char[] path) @safe
    {
        this._path = path;
    }

    ref const(String) method() scope return const @safe @nogc nothrow => this._method;
    ref const(String) path() scope return const @safe @nogc nothrow => this._path;
}

struct HttpResponse
{
    mixin HttpMessageNoGCCommon;

    private
    {
        uint   _status;
        String _reason;
    }

    @nogc nothrow:

    this(scope ref return typeof(this) src) @trusted // @safe: D can't figure out that the copy constructor... copies
    {
        this._status  = src._status;
        this._reason  = src._reason;
        this._headers = src._headers;
        this._body    = src._body;
    }

    void withStatus(uint status) @safe
    {
        this._status = status;
    }

    void withReason(scope const char[] reason) @safe
    {
        this._reason = reason;
    }

    ref const(String) reason() scope return const @safe @nogc nothrow => this._reason;
    uint status() scope return const @safe @nogc nothrow => this._status;
}