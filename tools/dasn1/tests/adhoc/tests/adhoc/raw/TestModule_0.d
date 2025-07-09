module tests.adhoc.raw.TestModule_0;

static import asn1 = juptune.data.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import buf = juptune.data.buffer;

struct MyBool
{
    private
    {
        asn1.Asn1Bool _value;
    }

    jres.Result set(
        asn1.Asn1Bool newValue,
    ) @nogc nothrow
    {
        _value = newValue;
        return jres.Result.noError;
    }

    asn1.Asn1Bool get(
    ) @nogc nothrow
    {
        return _value;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref buf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /++ FIELD - _value ++/
        typeof(_value) temp__value;
        result = typeof(temp__value).fromDecoding!ruleset(memory, temp__value, componentHeader.identifier);
        if(result.isError)
            return result;
        result = this.set(temp__value);
        if(result.isError)
            return result;

        return jres.Result.noError;
    }

}

struct MyChoice
{
    enum Choice
    {
        _FAILSAFE,
        bitstring,
        boolean,
    }

    union Value
    {
        asn1.Asn1BitString bitstring;
        asn1.Asn1Bool boolean;
    }

    // Sanity check: Ensuring that no types have a proper dtor, as they won't be called.
    import std.traits : hasElaborateDestructor;
    static assert(!hasElaborateDestructor!(asn1.Asn1BitString), "Report a bug if you see this.");
    static assert(!hasElaborateDestructor!(asn1.Asn1Bool), "Report a bug if you see this.");

    private
    {
        Choice _choice;
        Value _value;
    }

    jres.Result setBitstring(
        typeof(Value.bitstring) value,
    ) @nogc nothrow
    {
        _value.bitstring = value;
        _choice = Choice.bitstring;
        return jres.Result.noError;
    }

    typeof(Value.bitstring) getBitstring(
    ) @nogc nothrow
    {
        assert(_choice == Choice.bitstring, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'bitstring'");
        return _value.bitstring;
    }

    bool isBitstring(
    ) @nogc nothrow const
    {
        return _choice == Choice.bitstring;
    }

    jres.Result setBoolean(
        typeof(Value.boolean) value,
    ) @nogc nothrow
    {
        _value.boolean = value;
        _choice = Choice.boolean;
        return jres.Result.noError;
    }

    typeof(Value.boolean) getBoolean(
    ) @nogc nothrow
    {
        assert(_choice == Choice.boolean, "This '"~__traits(identifier, typeof(this))~" does not contain choice 'boolean'");
        return _value.boolean;
    }

    bool isBoolean(
    ) @nogc nothrow const
    {
        return _choice == Choice.boolean;
    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref buf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        if(ident.class_ == asn1.Asn1Identifier.Class.contextSpecific && ident.tag == 0)
        {
            /++ FIELD - bitstring ++/
            buf.MemoryReader memory_0bitstring;
                // EXPLICIT TAG - 0
                if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                    return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field bitstring a primitive tag was found when a constructed one was expected");
                if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "when reading EXPLICIT tag 0 for field bitstring the tag's class was expected to be contextSpecific");
                if(componentHeader.identifier.tag != 0)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "when reading EXPLICIT tag 0 for field bitstring the tag's value was expected to be contextSpecific");
                result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
                if(result.isError)
                    return result;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_0bitstring);
                if(result.isError)
                    return result;
            buf.MemoryReader memory_1bitstring;
                // EXPLICIT TAG - 10
                if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                    return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 10 for field bitstring a primitive tag was found when a constructed one was expected");
                if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.application)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "when reading EXPLICIT tag 10 for field bitstring the tag's class was expected to be application");
                if(componentHeader.identifier.tag != 10)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "when reading EXPLICIT tag 10 for field bitstring the tag's value was expected to be application");
                result = asn1.asn1DecodeComponentHeader!ruleset(memory_0bitstring, componentHeader);
                if(result.isError)
                    return result;
                result = asn1.asn1ReadContentBytes(memory_0bitstring, componentHeader.length, memory_1bitstring);
                if(result.isError)
                    return result;
            typeof(Value.bitstring) temp_bitstring;
            result = typeof(temp_bitstring).fromDecoding!ruleset(memory_1bitstring, temp_bitstring, componentHeader.identifier);
            if(result.isError)
                return result;
            result = this.setBitstring(temp_bitstring);
            if(result.isError)
                return result;

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 1)
        {
            /++ FIELD - boolean ++/
            typeof(Value.boolean) temp_boolean;
            result = typeof(temp_boolean).fromDecoding!ruleset(memory, temp_boolean, componentHeader.identifier);
            if(result.isError)
                return result;
            result = this.setBoolean(temp_boolean);
            if(result.isError)
                return result;

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type MyChoice the identifier tag & class were unable to match any known option");
    }

}
