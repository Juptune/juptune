/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.buffer;

public import std.system : Endian; // Required for some functions - so appropriate for public import

/++
 + A simple memory reader that allows reading bytes and integral types from a buffer.
 +
 + Notes:
 +  As Juptune is @nogc-first, the "easy" named functions follow the pattern of returning a boolean
 +  to indicate success, and then passing the result as an out parameter.
 +
 +  This is really cumbersome, so for @gc code there are "enforce" functions that throw an exception
 +  if there's not enough bytes to read, so the caller can use try-catch for error handling rather than
 +  checking the return value.
 + ++/
struct MemoryReader
{
    import std.traits : isIntegral;

    private
    {
        const(ubyte)[] _buffer;
        size_t _cursor;
    }

    @disable this(this); // Prevent accidental copying - helps enforce byRef usage

    /++
     + Constructs a new `MemoryReader` instance.
     +
     + Notes:
     +  This struct will pass direct slices of the buffer to the caller, so it's important to ensure that
     +  the buffer does not outlive the `MemoryReader` instance.
     +
     + Params:
     +  buffer = The buffer to read from.
     +  initialCursor = The initial cursor position.
     + ++/
    this(const(ubyte)[] buffer, size_t initialCursor = 0) @nogc @safe nothrow pure
    {
        this._buffer = buffer;
        this._cursor = initialCursor;
    }

    /++
     + Advances the cursor by the given number of bytes.
     +
     + Assertions:
     +  This function will assert if the cursor would overflow.
     +
     + Params:
     +  count = The number of bytes to advance the cursor by.
     + ++/
    void goForward(size_t count) @safe @nogc nothrow
    in(count <= size_t.max - this._cursor, "bug: integer overflow")
    {
        this._cursor += count;
    }

    /++
     + Moves the cursor back by the given number of bytes.
     +
     + Assertions:
     +  This function will assert if the cursor would underflow.
     +
     + Params:
     +  count = The number of bytes to move the cursor back by.
     + ++/
    void goBack(size_t count) @safe @nogc nothrow
    in(count <= this._cursor, "bug: integer underflow")
    {
        this._cursor -= count;
    }

    /++
     + Attempts to read a sequence of bytes from the buffer, and then optionally advances the cursor.
     +
     + Notes:
     +  Generally, you should use the `read*` and `peek*` aliases instead of this function directly.
     +
     +  If you're in @gc code, then you can also use the `enforce*Bytes` functions instead.
     +
     + Params:
     +  count = The number of bytes to read.
     +  advanceCursor = If true, the cursor will be advanced by the number of bytes read.
     +
     + Returns:
     +  `true` if there's enough bytes to read in the value, `false` otherwise.
     + ++/
    bool tryBytes(bool advanceCursor)(size_t count, out scope const(ubyte)[] result) @nogc @safe nothrow
    {
        if(this._cursor + count > this._buffer.length)
            return false;

        result = this._buffer[this._cursor..this._cursor + count];

        static if(advanceCursor)
            this._cursor += count;

        return true;
    }
    /// ditto
    alias readBytes = tryBytes!(true);
    /// ditto
    alias peekBytes = tryBytes!(false);

    /// The same thing as `tryBytes`, but throws an `Exception` if there's not enough bytes to read,
    /// which allows the function to return the value directly and rely on try-catch for error handling.
    const(ubyte)[] enforceBytes(bool advanceCursor)(size_t count) @safe
    {
        import std.exception : enforce;

        const(ubyte)[] result;
        enforce(this.tryBytes!(advanceCursor)(count, result), "Not enough bytes to read.");
        return result;
    }
    /// ditto
    alias enforceReadBytes = enforceBytes!(true);
    /// ditto
    alias enforcePeekBytes = enforceBytes!(false);

    bool tryIntegral24(Endian endian, bool advanceCursor)(out scope uint value) @safe @nogc nothrow
    {
        const(ubyte)[] bytes;
        const success = this.tryBytes!advanceCursor(3, bytes);
        if(!success)
            return false;

        static if(endian == Endian.littleEndian)
        {
            value = (
                (bytes[2] << 16) |
                (bytes[1] << 8) |
                bytes[0]
            );
        }
        else
        {
            value = (
                (bytes[0] << 16) |
                (bytes[1] << 8) |
                bytes[2]
            );
        }

        return true;
    }
    alias readU24BE = tryIntegral24!(Endian.bigEndian, true);
    alias readU24LE = tryIntegral24!(Endian.littleEndian, true);

    /++
     + Attempts to read an integral type from the buffer; automatically converting it from big/little endian
     + into the native endianess, and then optionally advances the cursor.
     +
     + Notes:
     +  If the given `IntT` is only a byte long, then the endian parameter is ignored.
     +
     +  `IntT` can be anything supported by `std.traits.isIntegral`, this includes numeric enums.
     +
     +  Generally, you should use the `read*` and `peek*` aliases instead of this function directly.
     +
     +  If you're in @gc code, then you can also use the `enforce*` functions instead.
     +
     + Params:
     +  IntT = The integral type to read.
     +  endian = The endianess of the integral type as stored within the underlying buffer.
     +  advanceCursor = If true, the cursor will be advanced by the size of the integral type.
     +
     + Returns:
     +  `true` if there's enough bytes to read in the value, `false` otherwise.
     + ++/
    bool tryIntegral(IntT, Endian endian, bool advanceCursor)(out scope IntT result) @nogc @safe nothrow
    if(isIntegral!IntT)
    {
        import std.bitmanip : bigEndianToNative, littleEndianToNative;

        if(this._cursor + IntT.sizeof > this._buffer.length)
            return false;

        static if(IntT.sizeof == 1)
        {
            result = cast(IntT)this._buffer[this._cursor];
        }
        else
        {
            ubyte[IntT.sizeof] bytes;
            bytes[0..$] = this._buffer[this._cursor..this._cursor + IntT.sizeof];
            static if(endian == Endian.bigEndian)
                result = bigEndianToNative!IntT(bytes);
            else
                result = littleEndianToNative!IntT(bytes);
        }

        static if(advanceCursor)
            this._cursor += IntT.sizeof;

        return true;
    }
    /// ditto
    alias readI8 = tryIntegral!(byte, Endian.littleEndian, true);
    /// ditto
    alias readU8 = tryIntegral!(ubyte, Endian.littleEndian, true);
    /// ditto
    alias readI16(Endian endian) = tryIntegral!(short, endian, true);
    /// ditto
    alias readU16(Endian endian) = tryIntegral!(ushort, endian, true);
    /// ditto
    alias readI32(Endian endian) = tryIntegral!(int, endian, true);
    /// ditto
    alias readU32(Endian endian) = tryIntegral!(uint, endian, true);
    /// ditto
    alias readI64(Endian endian) = tryIntegral!(long, endian, true);
    /// ditto
    alias readU64(Endian endian) = tryIntegral!(ulong, endian, true);
    /// ditto
    alias readI16BE = tryIntegral!(short, Endian.bigEndian, true);
    /// ditto
    alias readU16BE = tryIntegral!(ushort, Endian.bigEndian, true);
    /// ditto
    alias readI32BE = tryIntegral!(int, Endian.bigEndian, true);
    /// ditto
    alias readU32BE = tryIntegral!(uint, Endian.bigEndian, true);
    /// ditto
    alias readI64BE = tryIntegral!(long, Endian.bigEndian, true);
    /// ditto
    alias readU64BE = tryIntegral!(ulong, Endian.bigEndian, true);

    /// ditto
    alias peekI8 = tryIntegral!(byte, Endian.littleEndian, false);
    /// ditto
    alias peekU8 = tryIntegral!(ubyte, Endian.littleEndian, false);
    /// ditto
    alias peekI16(Endian endian) = tryIntegral!(short, endian, false);
    /// ditto
    alias peekU16(Endian endian) = tryIntegral!(ushort, endian, false);
    /// ditto
    alias peekI32(Endian endian) = tryIntegral!(int, endian, false);
    /// ditto
    alias peekU32(Endian endian) = tryIntegral!(uint, endian, false);
    /// ditto
    alias peekI64(Endian endian) = tryIntegral!(long, endian, false);
    /// ditto
    alias peekU64(Endian endian) = tryIntegral!(ulong, endian, false);

    /// The same thing as `tryIntegral`, but throws an `Exception` if there's not enough bytes to read,
    /// which allows the function to return the value directly and rely on try-catch for error handling.
    IntT enforceIntegral(IntT, Endian endian, bool advanceCursor)() @safe
    {
        import std.exception : enforce;

        IntT result;
        enforce(this.tryIntegral!(IntT, endian, advanceCursor)(result), "Not enough bytes to read.");
        return result;
    }
    /// ditto
    alias enforceReadI8 = enforceIntegral!(byte, Endian.littleEndian, true);
    /// ditto
    alias enforceReadU8 = enforceIntegral!(ubyte, Endian.littleEndian, true);
    /// ditto
    alias enforceReadI16(Endian endian) = enforceIntegral!(short, endian, true);
    /// ditto
    alias enforceReadU16(Endian endian) = enforceIntegral!(ushort, endian, true);
    /// ditto
    alias enforceReadI32(Endian endian) = enforceIntegral!(int, endian, true);
    /// ditto
    alias enforceReadU32(Endian endian) = enforceIntegral!(uint, endian, true);
    /// ditto
    alias enforceReadI64(Endian endian) = enforceIntegral!(long, endian, true);
    /// ditto
    alias enforceReadU64(Endian endian) = enforceIntegral!(ulong, endian, true);
    /// ditto
    alias enforcePeekI8 = enforceIntegral!(byte, Endian.littleEndian, false);
    /// ditto
    alias enforcePeekU8 = enforceIntegral!(ubyte, Endian.littleEndian, false);
    /// ditto
    alias enforcePeekI16(Endian endian) = enforceIntegral!(short, endian, false);
    /// ditto
    alias enforcePeekU16(Endian endian) = enforceIntegral!(ushort, endian, false);
    /// ditto
    alias enforcePeekI32(Endian endian) = enforceIntegral!(int, endian, false);
    /// ditto
    alias enforcePeekU32(Endian endian) = enforceIntegral!(uint, endian, false);
    /// ditto
    alias enforcePeekI64(Endian endian) = enforceIntegral!(long, endian, false);
    /// ditto
    alias enforcePeekU64(Endian endian) = enforceIntegral!(ulong, endian, false);

    /// Returns: The underlying buffer passed to the constructor.
    const(ubyte)[] buffer() const @safe @nogc nothrow pure => this._buffer;

    /// Returns: The number of bytes left in the buffer, for the current cursor position.
    size_t bytesLeft() const @safe @nogc nothrow pure
    in(this._cursor <= this._buffer.length, "bug: cursor is somehow out of bounds?")
    {
        return this._buffer.length - this._cursor;
    }

    /// Returns: The current cursor position.
    size_t cursor() const @safe @nogc nothrow pure => this._cursor;

    /++
     + Sets the cursor position.
     +
     + Params:
     +  newCursor: The new cursor position.
     + ++/
    void cursor(size_t newCursor) @safe @nogc nothrow
    { 
        this._cursor = newCursor; 
    }
}

struct MemoryWriter
{
    import std.traits : isIntegral;

    private
    {
        ubyte[] _buffer;
        size_t _cursor;
    }

    @disable this(this); // Prevent accidental copying - helps enforce byRef usage


    this(ubyte[] buffer, size_t initialCursor = 0) @nogc @safe nothrow pure
    {
        this._buffer = buffer;
        this._cursor = initialCursor;
    }

    /++
     + Advances the cursor by the given number of bytes.
     +
     + Assertions:
     +  This function will assert if the cursor would overflow.
     +
     + Params:
     +  count = The number of bytes to advance the cursor by.
     + ++/
    void goForward(size_t count) @safe @nogc nothrow
    in(count <= size_t.max - this._cursor, "bug: integer overflow")
    {
        this._cursor += count;
    }

    /++
     + Moves the cursor back by the given number of bytes.
     +
     + Assertions:
     +  This function will assert if the cursor would underflow.
     +
     + Params:
     +  count = The number of bytes to move the cursor back by.
     + ++/
    void goBack(size_t count) @safe @nogc nothrow
    in(count <= this._cursor, "bug: integer underflow")
    {
        this._cursor -= count;
    }

    bool tryBytes(const(ubyte)[] bytes) @safe @nogc nothrow
    in(bytes.length > 0, "bytes cannot be empty")
    {
        if(this.bytesLeft < bytes.length)
            return false;

        this._buffer[this._cursor..this._cursor+bytes.length] = bytes;
        this._cursor += bytes.length;
        return true;
    }

    const(ubyte)[] putBytesPartial(const(ubyte)[] bytes) @safe @nogc nothrow
    {
        import std.algorithm : min;
        const toWrite = min(bytes.length, this.bytesLeft);
        if(toWrite != 0)
        {
            this._buffer[this._cursor..this._cursor+toWrite] = bytes[0..toWrite];
            this._cursor += toWrite;
        }

        return toWrite < bytes.length ? bytes[toWrite..$] : null;
    }

    bool putU24(Endian endian)(uint value) @safe @nogc nothrow
    {
        import std.bitmanip : nativeToBigEndian, nativeToLittleEndian;

        if(this.bytesLeft < 3)
            return false;

        static if(endian == Endian.bigEndian)
        {
            const bytes = nativeToBigEndian(value);
            const slice = bytes[1..$];
            assert(bytes[0] == 0, "bug: value is larger than 24-bits");
        }
        else
        {
            const bytes = nativeToLittleEndian(value);
            const slice = bytes[0..3];
            assert(bytes[3] == 0, "bug: value is larger than 24-bits");
        }

        this._buffer[this._cursor..this._cursor+slice.length] = slice;
        this._cursor += slice.length;
        return true;
    }
    alias putU24BE = putU24!(Endian.bigEndian);
    alias putU24LE = putU24!(Endian.littleEndian);

    /++
     + Attempts to write an integral type into the buffer; automatically converting it from big/little endian
     + into the native endianess, and then advances the cursor.
     +
     + Notes:
     +  If the given `IntT` is only a byte long, then the endian parameter is ignored.
     +
     +  `IntT` can be anything supported by `std.traits.isIntegral`, this includes numeric enums.
     +
     +  Generally, you should use the `write*` aliases instead of this function directly.
     +
     +  If you're in @gc code, then you can also use the `enforce*` functions instead.
     +
     +  If there's not enough space in the buffer, then the buffer (and cursor) are left unmodified.
     +
     + Params:
     +  IntT = The integral type to write.
     +  endian = The endianess of the integral type to store within the buffer.
     +
     + Returns:
     +  `true` if there's enough space to write the value, `false` otherwise.
     + ++/
    bool tryIntegral(IntT, Endian endian)(IntT value) @safe @nogc nothrow
    if(isIntegral!IntT)
    {
        import std.bitmanip : nativeToBigEndian, nativeToLittleEndian;

        static if(IntT.sizeof == 1)
        {
            if(this.bytesLeft == 0)
                return false;
            this._buffer[this._cursor++] = cast(ubyte)value;
            return true;
        }
        else
        {
            if(this.bytesLeft < IntT.sizeof)
                return false;

            static if(endian == Endian.bigEndian)
                const bytes = nativeToBigEndian(value);
            else
                const bytes = nativeToLittleEndian(value);
            this._buffer[this._cursor..this._cursor+bytes.length] = bytes;
            this._cursor += bytes.length;
            return true;
        }
    }

    alias putU8 = tryIntegral!(ubyte, Endian.littleEndian);
    alias putI8 = tryIntegral!(byte, Endian.littleEndian);
    alias putU16LE = tryIntegral!(ushort, Endian.littleEndian);
    alias putU16BE = tryIntegral!(ushort, Endian.bigEndian);
    alias putU32LE = tryIntegral!(uint, Endian.littleEndian);
    alias putU32BE = tryIntegral!(uint, Endian.bigEndian);
    alias putU64LE = tryIntegral!(ulong, Endian.littleEndian);
    alias putU64BE = tryIntegral!(ulong, Endian.bigEndian);
    alias putI16LE = tryIntegral!(short, Endian.littleEndian);
    alias putI16BE = tryIntegral!(short, Endian.bigEndian);
    alias putI32LE = tryIntegral!(int, Endian.littleEndian);
    alias putI32BE = tryIntegral!(int, Endian.bigEndian);
    alias putI64LE = tryIntegral!(long, Endian.littleEndian);
    alias putI64BE = tryIntegral!(long, Endian.bigEndian);

    /// Returns: The underlying buffer passed to the constructor.
    ubyte[] buffer() @safe @nogc nothrow pure => this._buffer;

    ubyte[] usedBuffer() @safe @nogc nothrow => this._buffer[0..this._cursor];

    /// Returns: The number of bytes left in the buffer, for the current cursor position.
    size_t bytesLeft() const @safe @nogc nothrow pure
    in(this._cursor <= this._buffer.length, "bug: cursor is somehow out of bounds?")
    {
        return this._buffer.length - this._cursor;
    }

    /// Returns: The current cursor position.
    size_t cursor() const @safe @nogc nothrow pure => this._cursor;

    /++
     + Sets the cursor position.
     +
     + Params:
     +  newCursor: The new cursor position.
     + ++/
    void cursor(size_t newCursor) @safe @nogc nothrow
    { 
        this._cursor = newCursor; 
    }
}

/++++ Unit Tests ++++/
version(unittest):
private:

import core.exception : AssertError;
import std.exception : assertThrown;

@("MemoryReader - tryBytes")
@safe @nogc nothrow unittest
{
    static immutable ubyte[] buffer = [0x01, 0x02, 0x03, 0x04, 0x05];
    auto reader = MemoryReader(buffer);

    const(ubyte)[] result;
    assert(reader.peekBytes(5, result));
    assert(result == buffer[0..5]);
    assert(reader.cursor == 0);

    assert(reader.readBytes(2, result));
    assert(result == buffer[0..2]);
    assert(reader.cursor == 2);

    assert(reader.peekBytes(3, result));
    assert(result == buffer[2..5]);
    assert(reader.cursor == 2);

    reader.cursor = 4;
    assert(reader.readBytes(1, result));
    assert(result == buffer[4..5]);
    assert(reader.cursor == 5);

    assert(!reader.peekBytes(1, result));
    assert(!reader.readBytes(1, result));
}

@("MemoryReader - enforceBytes")
@safe unittest
{
    const ubyte[] buffer = [0x01, 0x02, 0x03, 0x04, 0x05];
    auto reader = MemoryReader(buffer);

    assert(reader.enforcePeekBytes(5) == buffer[0..5]);
    assert(reader.cursor == 0);

    assert(reader.enforceReadBytes(2) == buffer[0..2]);
    assert(reader.cursor == 2);

    assert(reader.enforcePeekBytes(3) == buffer[2..5]);
    assert(reader.cursor == 2);

    reader.cursor = 4;
    assert(reader.enforceReadBytes(1) == buffer[4..5]);
    assert(reader.cursor == 5);

    assertThrown!Exception(reader.enforcePeekBytes(1));
    assertThrown!Exception(reader.enforceReadBytes(1));
}

@("MemoryReader - tryIntegral")
@safe @nogc nothrow unittest
{
    static immutable ubyte[] buffer = [
        // Little Endian
        0x01, 
        0x02, 0x03, 
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

        // Big Endian
        0x01,
        0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    auto reader = MemoryReader(buffer);

    // 8
    byte i8;
    assert(reader.peekI8(i8));
    assert(i8 == 0x01);
    assert(reader.cursor == 0);

    assert(reader.readI8(i8));
    assert(i8 == 0x01);
    assert(reader.cursor == 1);

    // 16 (Little Endian)
    short i16;
    assert(reader.peekI16!(Endian.littleEndian)(i16));
    assert(i16 == 0x0302);
    assert(reader.cursor == 1);

    assert(reader.readI16!(Endian.littleEndian)(i16));
    assert(i16 == 0x0302);
    assert(reader.cursor == 3);

    // 32 (Little Endian)
    int i32;
    assert(reader.peekI32!(Endian.littleEndian)(i32));
    assert(i32 == 0x07060504);

    assert(reader.readI32!(Endian.littleEndian)(i32));
    assert(i32 == 0x07060504);
    assert(reader.cursor == 7);

    // 64 (Little Endian)
    long i64;
    assert(reader.peekI64!(Endian.littleEndian)(i64));
    assert(i64 == 0x0F0E0D0C0B0A0908);

    assert(reader.readI64!(Endian.littleEndian)(i64));
    assert(i64 == 0x0F0E0D0C0B0A0908);
    assert(reader.cursor == 15);

    // 8
    assert(reader.peekI8(i8));
    assert(i8 == 0x01);
    assert(reader.cursor == 15);

    assert(reader.readI8(i8));
    assert(i8 == 0x01);
    assert(reader.cursor == 16);

    // 16 (Big Endian)
    assert(reader.peekI16!(Endian.bigEndian)(i16));
    assert(i16 == 0x0203);
    assert(reader.cursor == 16);

    assert(reader.readI16!(Endian.bigEndian)(i16));
    assert(i16 == 0x0203);
    assert(reader.cursor == 18);

    // 32 (Big Endian)
    assert(reader.peekI32!(Endian.bigEndian)(i32));
    assert(i32 == 0x04050607);
    assert(reader.cursor == 18);

    assert(reader.readI32!(Endian.bigEndian)(i32));
    assert(i32 == 0x04050607);
    assert(reader.cursor == 22);

    // 64 (Big Endian)
    assert(reader.peekI64!(Endian.bigEndian)(i64));
    assert(i64 == 0x08090A0B0C0D0E0F);
    assert(reader.cursor == 22);

    assert(reader.readI64!(Endian.bigEndian)(i64));
    assert(i64 == 0x08090A0B0C0D0E0F);
    assert(reader.cursor == 30);

    // Reading past the end
    assert(!reader.peekI8(i8));
    assert(!reader.readI8(i8));
}

@("MemoryReader - enforceIntegral")
@safe unittest
{
    const ubyte[] buffer = [
        // Little Endian
        0x01, 
        0x02, 0x03, 
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,

        // Big Endian
        0x01,
        0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    ];
    auto reader = MemoryReader(buffer);

    // 8
    assert(reader.enforcePeekI8 == 0x01);
    assert(reader.cursor == 0);

    assert(reader.enforceReadI8 == 0x01);
    assert(reader.cursor == 1);

    // 16 (Little Endian)
    assert(reader.enforcePeekI16!(Endian.littleEndian) == 0x0302);
    assert(reader.cursor == 1);

    assert(reader.enforceReadI16!(Endian.littleEndian) == 0x0302);
    assert(reader.cursor == 3);

    // 32 (Little Endian)
    assert(reader.enforcePeekI32!(Endian.littleEndian) == 0x07060504);

    assert(reader.enforceReadI32!(Endian.littleEndian) == 0x07060504);
    assert(reader.cursor == 7);

    // 64 (Little Endian)
    assert(reader.enforcePeekI64!(Endian.littleEndian) == 0x0F0E0D0C0B0A0908);

    assert(reader.enforceReadI64!(Endian.littleEndian) == 0x0F0E0D0C0B0A0908);
    assert(reader.cursor == 15);

    // 8
    assert(reader.enforcePeekI8 == 0x01);
    assert(reader.cursor == 15);

    assert(reader.enforceReadI8 == 0x01);
    assert(reader.cursor == 16);

    // 16 (Big Endian)
    assert(reader.enforcePeekI16!(Endian.bigEndian) == 0x0203);
    assert(reader.cursor == 16);

    assert(reader.enforceReadI16!(Endian.bigEndian) == 0x0203);
    assert(reader.cursor == 18);

    // 32 (Big Endian)
    assert(reader.enforcePeekI32!(Endian.bigEndian) == 0x04050607);
    assert(reader.cursor == 18);

    assert(reader.enforceReadI32!(Endian.bigEndian) == 0x04050607);
    assert(reader.cursor == 22);

    // 64 (Big Endian)
    assert(reader.enforcePeekI64!(Endian.bigEndian) == 0x08090A0B0C0D0E0F);
    assert(reader.cursor == 22);

    assert(reader.enforceReadI64!(Endian.bigEndian) == 0x08090A0B0C0D0E0F);
    assert(reader.cursor == 30);

    // Reading past the end
    assertThrown!Exception(reader.enforcePeekI8);
    assertThrown!Exception(reader.enforceReadI8);
}

@("MemoryReader - bytesLeft")
@trusted unittest
{
    static immutable ubyte[] buffer = [0x01, 0x02, 0x03, 0x04, 0x05];
    auto reader = MemoryReader(buffer);

    assert(reader.bytesLeft == 5);
    reader.cursor = 3;
    assert(reader.bytesLeft == 2);

    reader._cursor = 200;
    assertThrown!AssertError(reader.bytesLeft);
}

@("MemoryReader - goForward & goBack")
@trusted unittest
{
    static immutable ubyte[] buffer = [0x01, 0x02];
    auto reader = MemoryReader(buffer);

    reader.goForward(2);
    assert(reader.cursor == 2);
    assertThrown!AssertError(reader.goForward(size_t.max));

    reader.goBack(1);
    assert(reader.cursor == 1);
    reader.goBack(1);
    assert(reader.cursor == 0);
    assertThrown!AssertError(reader.goBack(1));
}