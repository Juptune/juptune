module juptune.http.common;

import juptune.core.ds : Array, String2;

private mixin template HttpMessageNoGCCommon()
{
    private
    {
        Array!ubyte      _body;
        Array!HttpHeader _headers;
    }

    @nogc nothrow:

    /++
     + Appends the given bytes to the body of the message.
     + ++/
    void putBody(scope const ubyte[] body) @trusted // TODO: Look into why Array.put isn't marked @trusted or @safe
    {
        this._body ~= body;
    }

    /++
     + Sets the given header to the given value. If the value is empty, the header is removed.
     +
     + Notes:
     +  The key and value will be copied into a heap allocated string.
     +
     +  The key and value types are templated, so that you can use any type supported by `String2`.
     +
     + Params:
     +  key   = The name of the header to set.
     +  value = The value to set the header to.
     + ++/
    void setHeader(KeyT, ValueT)(scope KeyT key, scope ValueT value) @trusted // ditto todo as putBody
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
                    header._value = String2(value);
                return;
            }
        }

        if(value.length != 0)
            this._headers ~= HttpHeader(key, value);
    }

    /++
     + Tries to get the header with the given name.
     +
     + Notes:
     +  The key type is templated, so that you can use any type supported by `String2`.
     +
     + Params:
     +  key      = The name of the header to get.
     +  wasFound = Set to true if the header was found, false otherwise.
     +
     + Returns:
     +  The header with the given name, or an empty header if it wasn't found.
     + ++/
    HttpHeader tryGetHeader(KeyT)(scope KeyT key, scope out bool wasFound) @safe
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

    /// The headers of the message.
    /// Note: The return type is unstable - I'm doubt it'll stay as an `Array` in the long term.
    ref const(Array!HttpHeader) headers() scope return const @safe @nogc nothrow => this._headers;

    /// The body of the message.
    ref const(Array!ubyte) body() scope return const @safe @nogc nothrow => this._body;
}

/++
 + Represents a single HTTP header.
 + ++/
struct HttpHeader
{
    private 
    {
        String2 _name;
        String2 _value;
    }

    /++ 
     + Creates a new header with the given name and value.
     +
     + Notes:
     +  The name will be canonicalized in-place. Errors in the name will be ignored as ctors can't
     +  return values without using `out` parameters, and any code that generates a HTTP request should
     +  validate and catch errors anyway.
     +
     +  The name and value will be copied into an internal string.
     +
     +  If the name is of type `String2`, it will have its payload cloned into a new string as this ctor
     +  needs to modify the string in place.
     +
     + Params:
     +  name  = The name of the header. This can be any type supported by `String2`'s ctor.
     +  value = The value of the header. This can be any type supported by `String2`'s ctor.
     + ++/
    this(NameT, ValueT)(scope NameT name, scope ValueT value) @trusted // @safe: The const removal is safe
    {
        import juptune.http.v1 : http1CanonicalHeaderNameInPlace;

        this._value = String2(value);

        static if(is(NameT == String2))
            this._name = String2(name.sliceMaybeFromStack); // Clones the payload.
        else
            this._name = String2(name);

        // NOTE: While it would be nice to check the validation result, this
        //       should get caught in the writer anyway. The annoyance of constructors :(
        scope nameSlice = cast(ubyte[])this._name.sliceMaybeFromStack; // Breaks the type system, but this is the only copy at this point, so it's basically safe.
        http1CanonicalHeaderNameInPlace(nameSlice);
    }

    /// Copy ctor
    this(scope ref return typeof(this) src) @trusted @nogc nothrow // @safe: D can't figure out that the copy constructor... copies
    {
        this._name  = src._name;
        this._value = src._value;
    }

    /// The name of the header.
    ref const(String2) name() scope return const @safe @nogc nothrow => this._name;

    /// The value of the header.
    ref const(String2) value() scope return const @safe @nogc nothrow => this._value;
}

/++
 + Represents a HTTP request with a method; headers; and a body.
 + ++/
struct HttpRequest
{
    mixin HttpMessageNoGCCommon;

    private
    {
        String2 _method;
        String2 _path;
    }

    @nogc nothrow:

    /// Copy ctor
    this(scope ref return typeof(this) src) @trusted // @safe: D can't figure out that the copy constructor... copies
    {
        this._method  = src._method;
        this._path    = src._path;
        this._headers = src._headers;
        this._body    = src._body;
    }

    /++ 
     + Sets the method of the request.
     +
     + Notes:
     +  The method type is templated so that you can use any type supported by `String2`.
     +
     + Params:
     +  method = The method to set the request to.
     + ++/
    void withMethod(MethodT)(scope MethodT method)
    {
        this._method = String2(method);
    }

    /++ 
     + Sets the path of the request.
     +
     + Notes:
     +  The path type is templated so that you can use any type supported by `String2`.
     +
     + Params:
     +  path = The path to set the request to.
     + ++/
    void withPath(PathT)(scope PathT path)
    {
        this._path = String2(path);
    }

    /// The method of the request.
    ref const(String2) method() scope return const @safe @nogc nothrow => this._method;

    /// The path of the request.
    ref const(String2) path() scope return const @safe @nogc nothrow => this._path;
}

/++
 + Represents a HTTP response with a status code + reason; headers; a body, and trailers.
 + ++/
struct HttpResponse
{
    mixin HttpMessageNoGCCommon;

    private
    {
        uint   _status;
        String2 _reason;
    }

    @nogc nothrow:

    /// Copy ctor
    this(scope ref return typeof(this) src) @trusted // @safe: D can't figure out that the copy constructor... copies
    {
        this._status  = src._status;
        this._reason  = src._reason;
        this._headers = src._headers;
        this._body    = src._body;
    }

    /++ 
     + Sets the status of the response.
     +
     + Params:
     +  status = The status to set the response to.
     + ++/
    void withStatus(uint status) @safe
    {
        this._status = status;
    }

    /++ 
     + Sets the reason of the response.
     +
     + Notes:
     +  The reason type is templated so that you can use any type supported by `String2`.
     +
     + Params:
     +  reason = The reason to set the response to.
     + ++/
    void withReason(ReasonT)(scope ReasonT reason)
    {
        this._reason = String2(reason);
    }

    /// The status of the response.
    ref const(String2) reason() scope return const @safe @nogc nothrow => this._reason;

    /// The reason of the response.
    uint status() const @safe @nogc nothrow => this._status;
}