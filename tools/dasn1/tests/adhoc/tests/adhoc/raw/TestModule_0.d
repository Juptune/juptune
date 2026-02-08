module tests.adhoc.raw.TestModule_0;

static import tcon = std.typecons;
static import asn1 = juptune.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string;
static import utf8 = juptune.data.utf8;

struct MyBool
{
    private
    {
        asn1.Asn1Bool _value;
        bool _isSet;
    }

    jres.Result set(
        asn1.Asn1Bool newValue,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _value = newValue;
        _isSet = true;
        return jres.Result.noError;
    }

    asn1.Asn1Bool get(
    ) @nogc nothrow
    {
        assert(_isSet, "Cannot call get() when no value has been set!");
        return _value;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        static if(__traits(hasMember, asn1.Asn1Bool, "toString"))
            _value.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>");
        }
        sink("\n");
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
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
            return result.wrapError("when decoding field '_value' in type "~__traits(identifier, typeof(this))~":");
        result = this.set(temp__value);
        if(result.isError)
            return result.wrapError("when setting field '_value' in type "~__traits(identifier, typeof(this))~":");

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

    jres.Result match(
        scope jres.Result delegate(typeof(Value.bitstring)) @nogc nothrow handle_bitstring,
        scope jres.Result delegate(typeof(Value.boolean)) @nogc nothrow handle_boolean,
    ) @nogc nothrow
    {
        if(_choice == Choice.bitstring)
            return handle_bitstring(_value.bitstring);
        if(_choice == Choice.boolean)
            return handle_boolean(_value.boolean);
        assert(false, "attempted to use an uninitialised MyChoice!");

    }

    jres.Result matchGC(
        scope jres.Result delegate(typeof(Value.bitstring))  handle_bitstring,
        scope jres.Result delegate(typeof(Value.boolean))  handle_boolean,
    ) 
    {
        if(_choice == Choice.bitstring)
            return handle_bitstring(_value.bitstring);
        if(_choice == Choice.boolean)
            return handle_boolean(_value.boolean);
        assert(false, "attempted to use an uninitialised MyChoice!");

    }

    jres.Result setBitstring(
        typeof(Value.bitstring) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
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
        jres.Result result = jres.Result.noError;
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
        scope ref jbuf.MemoryReader memory,
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
            jbuf.MemoryReader memory_0bitstring;
                // EXPLICIT TAG - 0
                if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                    return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 0 for field bitstring a primitive tag was found when a constructed one was expected");
                if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.contextSpecific)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 0 for field 'bitstring' the tag's class was expected to be contextSpecific", jstr.String("class was ", componentHeader.identifier.class_));
                if(componentHeader.identifier.tag != 0)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 0 for field 'bitstring' the tag's value was expected to be 0", jstr.String("tag value was ", componentHeader.identifier.tag));
                result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
                if(result.isError)
                    return result.wrapError("when decoding header of field 'bitstring' in type "~__traits(identifier, typeof(this))~":");
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_0bitstring);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'bitstring' in type "~__traits(identifier, typeof(this))~":");
            jbuf.MemoryReader memory_1bitstring;
                // EXPLICIT TAG - 10
                if(componentHeader.identifier.encoding != asn1.Asn1Identifier.Encoding.constructed)
                    return jres.Result.make(asn1.Asn1DecodeError.constructionIsPrimitive, "when reading EXPLICIT tag 10 for field bitstring a primitive tag was found when a constructed one was expected");
                if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.application)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for TODO TODO when reading EXPLICIT tag 10 for field 'bitstring' the tag's class was expected to be application", jstr.String("class was ", componentHeader.identifier.class_));
                if(componentHeader.identifier.tag != 10)
                    return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for TODO TODO when reading EXPLICIT tag 10 for field 'bitstring' the tag's value was expected to be 10", jstr.String("tag value was ", componentHeader.identifier.tag));
                result = asn1.asn1DecodeComponentHeader!ruleset(memory_0bitstring, componentHeader);
                if(result.isError)
                    return result.wrapError("when decoding header of field 'bitstring' in type "~__traits(identifier, typeof(this))~":");
                result = asn1.asn1ReadContentBytes(memory_0bitstring, componentHeader.length, memory_1bitstring);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'bitstring' in type "~__traits(identifier, typeof(this))~":");
            typeof(Value.bitstring) temp_bitstring;
            result = typeof(temp_bitstring).fromDecoding!ruleset(memory_1bitstring, temp_bitstring, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'bitstring' in type "~__traits(identifier, typeof(this))~":");
            result = this.setBitstring(temp_bitstring);
            if(result.isError)
                return result.wrapError("when setting field 'bitstring' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        if(ident.class_ == asn1.Asn1Identifier.Class.universal && ident.tag == 1)
        {
            /++ FIELD - boolean ++/
            typeof(Value.boolean) temp_boolean;
            result = typeof(temp_boolean).fromDecoding!ruleset(memory, temp_boolean, componentHeader.identifier);
            if(result.isError)
                return result.wrapError("when decoding field 'boolean' in type "~__traits(identifier, typeof(this))~":");
            result = this.setBoolean(temp_boolean);
            if(result.isError)
                return result.wrapError("when setting field 'boolean' in type "~__traits(identifier, typeof(this))~":");

            return jres.Result.noError;
        }

        return jres.Result.make(asn1.Asn1DecodeError.choiceHasNoMatch, "when decoding CHOICE of type MyChoice the identifier tag & class were unable to match any known option");
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        if(isBitstring)
        {
            depth++;
            putIndent();
            sink("bitstring: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getBitstring()), "toString"))
                _value.bitstring.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        if(isBoolean)
        {
            depth++;
            putIndent();
            sink("boolean: ");
            sink("\n");
            static if(__traits(hasMember, typeof(getBoolean()), "toString"))
                _value.boolean.toString(sink, depth+1);
            else
                {
                putIndent();
                sink("<no toString impl>\n");
            }
            depth--;
        }
        depth--;

    }

}

struct MySequence
{
    private
    {
        bool _isSet_a;
        asn1.Asn1Bool _a;
        bool _isSet_b;
        asn1.Asn1Bool _b;
        bool _isSet_c;
        asn1.Asn1Bool _c;
    }

    jres.Result setA(
        typeof(_a) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_a = true;
        _a = value;
        return jres.Result.noError;
    }

    typeof(_a) getA(
    ) @nogc nothrow
    {
        assert(_isSet_a, "Non-optional field 'a' has not been set yet - please use validate() to check!");
        return _a;
    }

    jres.Result setB(
        typeof(_b) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_b = true;
        _b = value;
        return jres.Result.noError;
    }

    jres.Result setB(
        tcon.Nullable!(asn1.Asn1Bool) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        if(!value.isNull)
        {
            return setB(value.get());
        }
        else
            _isSet_b = false;
        return jres.Result.noError;
    }

    tcon.Nullable!(asn1.Asn1Bool) getB(
    ) @nogc nothrow
    {
        if(_isSet_b)
            return typeof(return)(_b);
        return typeof(return).init;
    }

    jres.Result setC(
        typeof(_c) value,
    ) @nogc nothrow
    {
        jres.Result result = jres.Result.noError;
        _isSet_c = true;
        _c = value;
        return jres.Result.noError;
    }

    typeof(_c) getC(
    ) @nogc nothrow
    {
        assert(_isSet_c, "Non-optional field 'c' has not been set yet - please use validate() to check!");
        return _c;
    }

    jres.Result validate(
    ) @nogc nothrow
    {
        if(!_isSet_a)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type MySequence non-optional field 'a' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        if(!_isSet_c)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceMissingField, "for SEQUENCE type MySequence non-optional field 'c' has not been given a value - either because its setter wasn't called, or the decoded data stream did not provide the field.");
        return jres.Result.noError;
    }

    private alias _toStringTestInstantiation = toString!(void delegate(scope const(char)[]) @nogc nothrow);
    void toString(SinkT)(
        scope SinkT sink,
        int depth = 0,
    ) 
    {
        void putIndent(){ foreach(i; 0..depth) sink("  "); }
        
        putIndent();
        sink("["~__traits(identifier, typeof(this))~"]\n");
        depth++;
        putIndent();
        depth++;
        sink("a: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_a), "toString"))
            _a.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("b: ");
        sink("\n");
        if(_isSet_b)
        {
            static if(__traits(hasMember, typeof(_b), "toString"))
                _b.toString(sink, depth+1);
            else
            {
                putIndent();
                sink("<no toString impl>\n");
            }
        }
        else
        {
            putIndent();
            sink("<optional null>\n");
        }
        depth--;
        putIndent();
        depth++;
        sink("c: ");
        sink("\n");
        static if(__traits(hasMember, typeof(_c), "toString"))
            _c.toString(sink, depth+1);
        else
        {
            putIndent();
            sink("<no toString impl>\n");
        }
        depth--;
        depth--;

    }

    private alias testInstantiation = fromDecoding!(asn1.Asn1Ruleset.der);
    jres.Result fromDecoding(asn1.Asn1Ruleset ruleset)(
        scope ref jbuf.MemoryReader memory,
        const asn1.Asn1Identifier ident,
    ) 
    {
        auto result = jres.Result.noError;
        asn1.Asn1ComponentHeader componentHeader;
        componentHeader.identifier = ident;
        this = typeof(this).init;

        /+++ TAG FOR FIELD: a +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'a' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE MySequence when reading top level tag 1 for field 'a' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 1)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE MySequence when reading top level tag 1 for field 'a' the tag's value was expected to be 1", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_a;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_a);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'a' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - a ++/
        typeof(_a) temp_a;
        result = typeof(temp_a).fromDecoding!ruleset(memory_a, temp_a, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'a' in type "~__traits(identifier, typeof(this))~":");
        result = this.setA(temp_a);
        if(result.isError)
            return result.wrapError("when setting field 'a' in type "~__traits(identifier, typeof(this))~":");

        
        /+++ TAG FOR FIELD: b +++/
        auto backtrack_b = jbuf.MemoryReader(memory.buffer, memory.cursor);
        if(memory.bytesLeft != 0)
        {
            result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
            if(result.isError)
                return result.wrapError("when decoding header of field 'b' in type "~__traits(identifier, typeof(this))~":");
            if(componentHeader.identifier.class_ == asn1.Asn1Identifier.Class.universal && componentHeader.identifier.tag == 1)
            {
                jbuf.MemoryReader memory_b;
                result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_b);
                if(result.isError)
                    return result.wrapError("when reading content bytes of field 'b' in type "~__traits(identifier, typeof(this))~":");
                /++ FIELD - b ++/
                typeof(_b) temp_b;
                result = typeof(temp_b).fromDecoding!ruleset(memory_b, temp_b, componentHeader.identifier);
                if(result.isError)
                    return result.wrapError("when decoding field 'b' in type "~__traits(identifier, typeof(this))~":");
                result = this.setB(temp_b);
                if(result.isError)
                    return result.wrapError("when setting field 'b' in type "~__traits(identifier, typeof(this))~":");

            }
            else
            {
                memory = jbuf.MemoryReader(backtrack_b.buffer, backtrack_b.cursor);
            }
        }
        
        /+++ TAG FOR FIELD: c +++/
        result = asn1.asn1DecodeComponentHeader!ruleset(memory, componentHeader);
        if(result.isError)
            return result.wrapError("when decoding header of field 'c' in type "~__traits(identifier, typeof(this))~":");
        if(componentHeader.identifier.class_ != asn1.Asn1Identifier.Class.universal)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidClass, "for SEQUENCE MySequence when reading top level tag 2 for field 'c' the tag's class was expected to be universal", jstr.String("class was ", componentHeader.identifier.class_));
        if(componentHeader.identifier.tag != 2)
            return jres.Result.make(asn1.Asn1DecodeError.identifierHasInvalidTag, "for SEQUENCE MySequence when reading top level tag 2 for field 'c' the tag's value was expected to be 2", jstr.String("tag value was ", componentHeader.identifier.tag));
        jbuf.MemoryReader memory_c;
        result = asn1.asn1ReadContentBytes(memory, componentHeader.length, memory_c);
        if(result.isError)
            return result.wrapError("when reading content bytes of field 'c' in type "~__traits(identifier, typeof(this))~":");
        /++ FIELD - c ++/
        typeof(_c) temp_c;
        result = typeof(temp_c).fromDecoding!ruleset(memory_c, temp_c, componentHeader.identifier);
        if(result.isError)
            return result.wrapError("when decoding field 'c' in type "~__traits(identifier, typeof(this))~":");
        result = this.setC(temp_c);
        if(result.isError)
            return result.wrapError("when setting field 'c' in type "~__traits(identifier, typeof(this))~":");

        
        if(memory.bytesLeft != 0)
            return jres.Result.make(asn1.Asn1DecodeError.sequenceHasExtraData, "when decoding non-extensible SEQUENCE MySequence there were unsused content bytes after attempting to decode all known fields - this is either due to a decoder bug; an outdated ASN.1 spec, or malformed input");
        return this.validate();
    }

}
