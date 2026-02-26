/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.postgres.client;

import core.time : Duration;

import juptune.core.util    : Result;
import juptune.data         : MemoryReader;
import juptune.event        : IpAddress;
import juptune.postgres.protocol.datatypes 
    : 
        PostgresDataTypeOid, 
        PostgresDate, 
        PostgresTimestamp, 
        PostgresTimetz, 
        PostgresTimestamptz
    ;
import juptune.postgres.protocol.connection 
    : 
        PostgresProtocol, 
        PostgresProtocolConfig, 
        PostgresConnectInfo, 
        PostgresColumnDescription,
        PostgresParameters
    ;

private template OutgoingWireFormatFor(T)
{
    // Default to always using text for now, even if its slower.
    enum OutgoingWireFormatFor = PostgresColumnDescription.Format.text;
}

// A `Result` error enum.
enum PostgresClientError
{
    none,
    columnCountMismatch,
    typeMismatch,
    noData,
}

/++
 + A higher-level wrapper around `PostgresProtocol` that makes it much easier to convert
 + D types into their respective Postgres wire format, and vice-versa.
 +
 + Most code should be using this instead of `PostgresProtocol`.
 +
 + Usage:
 +  First, call `.connect` to connect and authenticate against a postgres instance.
 +
 +  If you want to execute a query without handling any return results, then use `.exec` and `.execGc`.
 +
 +  If you want to execute a query and handle a single returned row, use `.rowScanner().queryRow`.
 +
 +  If you want to execute a query and handle multiple returned rows, use `.rowScanner().query` and `.rowScanner().queryGc`.
 +
 +  If you want to execute multiple statements in one query, please use `.protocol` to access the underlying `PostgresProtocol`, and then
 +  call `.simpleQuery` on it.
 + ++/
struct PostgresClient
{
    private
    {
        PostgresProtocol _protocol;
    }

    /// Exactly the same as `PostgtresProtocol.this`
    this(PostgresProtocolConfig config)
    {
        this._protocol = PostgresProtocol(config);
    }

    /// Exactly the same as `PostgresProtocol.connect`
    Result connect(IpAddress address, scope PostgresConnectInfo connectInfo) @nogc nothrow
    {
        return this._protocol.connect(address, connectInfo);
    }

    /// Returns: The underlying `PostgresProtocol`, for certain use cases this higher-level client doesn't provide.
    scope ref PostgresProtocol protocol() @nogc nothrow
    {
        return this._protocol;
    }

    /++
     + Executes a query without reading in any of its returned rows.
     +
     + Notes:
     +  This is essentially the same as `RowScanner.query` but without the row scanning side of things, so
     +  please refer to that function's documentation.
     + ++/
    Result exec(QueryArgs...)(scope const(char)[] query, scope QueryArgs args)
    {
        // Prepare the statement
        auto result = this._protocol.prepare("", query, null);
        if(result.isError)
            return result;

        // Setup binder delegate
        scope bind = (const int paramIndex, scope ref PostgresProtocol psql, scope out bool moreParamsLeftToBind) 
        {
            Result result = Result.noError;

            Switch: final switch(paramIndex)
            {
                static foreach(i, QueryArgT; QueryArgs)
                {
                    case i:
                        result = bindParameter!QueryArgT(args[i], psql);
                        if(result.isError)
                            return result;
                        break Switch;
                }
            }

            moreParamsLeftToBind = ((paramIndex + 1) < QueryArgs.length);
            return Result.noError;
        };

        static if(QueryArgs.length == 0)
            scope typeof(bind) bindFunc = null;
        else
            scope typeof(bind) bindFunc = bind;

        // Execute the statement, but don't bother reading in any of the results
        return this._protocol.bindDescribeExecuteInfer!(
            typeof(bind),
            PostgresProtocol.ColumnDescriptionHandlerT,
            PostgresProtocol.DataRowHandlerT,
        )(
            "",
            null, // For _now_ we'll just always use the textual format for parameters.
            null, // We're not parsing the results, so we don't care about their format.
            bindParameterOrNull: bindFunc,
            onRowDescriptionOrNull: null,
            onDataRowOrNull: null,
        );
    }

    /++
     + Constructs a row scanner that'll read any returned rows into the provided set of values.
     +
     + Notes:
     +  While you _can_ store the returned scanner inside of a variable, it's ill-advised to do so as it
     +  contains direct pointers to the stack. It's recommended that you immediately chain into a query call,
     +  e.g. `.rowScanner().queryRow()`.
     +
     +  The order of the values in `values` should match the order and data types of the columns returned by your query.
     +
     +  Please see the documentation of `RowScanner.query` for a list of all types that can be passed into `values`.
     +
     + Params:
     +  values = The values to store query results into.
     +
     + Returns:
     +  A `RowScanner` that can execute queries and scan the results into the provided value set 
     +  (please treat it as an internal struct, rather than a public thing you can pass around willy-nilly).
     + ++/
    RowScanner!ReturnValues rowScanner(ReturnValues...)(scope return ref ReturnValues values)
    {
        typeof(return).ReturnValuePointers pointers;
        foreach(i, ref value; values)
            pointers[i] = &value;

        return typeof(return)(&this._protocol, pointers);
    }

    /// Intentionally public for documentation - PLEASE do not use this directly, only use `.rowScanner`
    struct RowScanner(ReturnValues...)
    {
        /++
         + Executes a query, and for each row it will scan the data into previously provided value set, calling
         + `onRow` after each row has been scanned.
         +
         + Types:
         +  The following types are supported within the return value set. Unless specified, this is also the list of types that can
         +  be provided as query parameter arguments (via `args`).
         +
         +  * ALL Postgres types can be converted into any of the supported D string types, even data types that are otherwise completely unsupported by Juptune.
         +  * Native D char slices (`const(char)[]` and `string`) are supported. The GC is used to perform a full copy of the data into these values.
         +  * Juptune's `String` type is supported. This is the main `@nogc` alternative for strings. The value is still fully copied as with `@gc` strings.
         +  * All native signed integers are supported and must correspond to the Postgres type with the same byte count. e.g. `short` and `SMALLINT` is fine, `int` and `SMALLINT` isn't.
         +      * Notably `byte` isn't actually supported since Postgres lacks a one-byte integral type.
         +      * Unsigned types aren't supported as Postgres itself doesn't support unsigned integers.
         +  * `bool`
         +  * `Duration` (for `TIME`)
         +  * `PostgresTimetz` (for `TIME WITH TIME ZONE`)
         +  * `PostgresDate` (for `DATE`)
         +  * `PostgresTimestamp` (for `TIMESTAMP`)
         +  * `PostgresTimestamptz` (for `TIMESTAMP WITH TIME ZONE`)
         +
         + Inference:
         +  Internally there's a templated function who's `@nogc`-ness is inferred by whether any of your return value set types
         +  requires the GC or not. e.g. If you use `string s; rowScanner(s);`, then you **must** use `queryGc` instead of `query`,
         +  as you'll otherwise get an error about `@nogc`.
         +
         + Params:
         +  query = The query to execute.
         +  args  = All arguments to pass into the query. Reminder that placeholders look like "$1" (for args[0]), "$2" (args[1]), etc.
         +
         + Throws:
         +  `PostgresClientError.columnCountMismatch` if the amount of columns returned by the query is not exactly the same
         +  as the amount of values previously passed into the value set.
         +
         +  `PostgresClientError.typeMismatch` if one of the columns returned by the query is unable to be converted
         +  into its relative D type (e.g. the first column is a `DATE` but the 0th value in the value set is a `bool`).
         +
         +  Anything that `onRow` throws.
         +
         +  Anything that `PostgresProtocol.prepare`, and `PostgresProtocol.bindDescribeExec` can.
         +  
         + Returns:
         +  An errorful `Result` if something went wrong.
         + ++/
        Result query(QueryArgs...)(
            scope const(char)[] query,
            scope QueryArgs args,
            scope Result delegate() @nogc nothrow onRow,
        ) @nogc nothrow
        {
            return this.queryImpl!false(query, args, onRow);
        }

        /// ditto.
        Result queryGc(QueryArgs...)(
            scope const(char)[] query,
            scope QueryArgs args,
            scope Result delegate() onRow,
        )
        {
            return this.queryImpl!false(query, args, onRow);
        }

        /++
         + Functions mostly the same as `query`, with a few distinct changes.
         +
         + 1. Only the first row is scanned, all other rows are discarded (hence why there's no onRow callback).
         + 2. If no rows are generated then a `PostgresClientError.noData` error is generated.
         +    This is less of an actual error, and more a provide an easier way of detecting the "no rows returned" case.
         +    (The values in the return value set are undefined).
         +
         + Throws:
         +  `PostgresClientError.noData` if no rows are returned by your query.
         +
         +  Everything that `query` can.
         + ++/
        Result queryRow(QueryArgs...)(
            scope const(char)[] query,
            scope QueryArgs args,
        )
        {
            return this.queryImpl!true(query, args, () => Result.noError);
        }

        @disable this(this);

        private:

        import std.meta : staticMap;

        // This is an insanely hacky way to get a somewhat reasonable @nogc interface lol.
        alias Pointer(T) = T*;
        alias ReturnValuePointers = staticMap!(Pointer, ReturnValues);

        PostgresProtocol* _protocol;
        ReturnValuePointers _pointers;

        Result queryImpl(bool Once, HandlerT, QueryArgs...)(
            scope const(char)[] query, 
            scope QueryArgs args,
            scope HandlerT onRow,
        )
        {
            static struct FormatAndType
            {
                PostgresColumnDescription.Format format;
                PostgresDataTypeOid type;
            }

            FormatAndType[ReturnValues.length] retValueFormats;

            // Prepare the statement
            auto result = this._protocol.prepare("", query, null);
            if(result.isError)
                return result;

            // Setup delegates
            scope bind = (const int paramIndex, scope ref PostgresProtocol psql, scope out bool moreParamsLeftToBind) 
            {
                Result result = Result.noError;

                static foreach(i, QueryArgT; QueryArgs)
                {
                    result = bindParameter!QueryArgT(args[i], psql);
                    if(result.isError)
                        return result;
                }

                moreParamsLeftToBind = ((paramIndex + 1) < QueryArgs.length);
                return Result.noError;
            };

            scope onRowDescription = (ushort columnCount, scope PostgresProtocol.NextColumnDescriptionT nextDescription){ // @suppress(dscanner.style.long_line)
                import juptune.core.ds : String;

                if(columnCount != ReturnValues.length)
                {
                    return Result.make(
                        PostgresClientError.columnCountMismatch,
                        "the amount of return values provided by the query, doesn't match the amount of return values specified by the template parameters", // @suppress(dscanner.style.long_line)
                        String("exepcted ", ReturnValues.length, " return values, but got ", columnCount)
                    );
                }

                Result result = Result.noError;
                PostgresColumnDescription desc;

                static foreach(i, ReturnValueT; ReturnValues)
                {
                    result = nextDescription(desc);
                    if(result.isError)
                        return result;
                    result = areCompatibleTypes!ReturnValueT(
                        desc, 
                        retValueFormats[i].format, 
                        retValueFormats[i].type
                    );
                    if(result.isError)
                        return result;
                }

                return Result.noError;
            };

            bool once;
            scope onDataRow = (ushort _, scope PostgresProtocol.NextColumnDataT nextData) {
                static if(Once)
                {
                    if(once)
                        return Result.noError;
                    once = true;
                }

                MemoryReader reader;
                bool isNull;

                Result result = Result.noError;
                static foreach(i, ReturnValueT; ReturnValues)
                {
                    result = nextData(reader, isNull);
                    if(result.isError)
                        return result;
                    assert(!isNull, "TODO: Support null");

                    result = decodeResult(
                        *this._pointers[i], 
                        reader, 
                        retValueFormats[i].format, 
                        retValueFormats[i].type,
                        this._protocol.params
                    );
                    if(result.isError)
                        return result;
                }

                return onRow();
            };

            static if(QueryArgs.length == 0)
                scope typeof(bind) bindFunc = null;
            else
                scope typeof(bind) bindFunc = bind;

            // Execute the statement, and read a single result
            result = this._protocol.bindDescribeExecuteInfer!(
                typeof(bind),
                typeof(onRowDescription),
                typeof(onDataRow),
            )(
                "",
                null, // For _now_ we'll just always use the textual format for parameters.
                null, // For _now_ we'll also just always use the textual format for return results.
                bindParameterOrNull: bindFunc,
                onRowDescriptionOrNull: onRowDescription,
                onDataRowOrNull: onDataRow,
            );
            if(result.isError)
                return result;

            static if(Once)
            {
                if(!once) // If this isn't set, then onDataRow was never called, meaning we have no data.
                    return Result.make(PostgresClientError.noData, "queryRow produced no rows");
            }
            
            return Result.noError;
        }
    }
}

private Result bindParameter(ParamT)(scope ParamT param, scope ref PostgresProtocol psql)
{
    import juptune.postgres.protocol.datatypes; // Intentionally imports everything.

    enum WireFormat = OutgoingWireFormatFor!ParamT;
    enum isText = (WireFormat == PostgresColumnDescription.Format.text);

    static if(is(ParamT : const(char)[]))
    {
        static assert(isText);
        return encodeTextText(psql, param, psql.params);
    }
    else static if(is(ParamT : bool))
    {
        static assert(isText);
        return encodeBooleanText(psql, param, psql.params);
    }
    else static if(
        __traits(isIntegral, ParamT) 
        && is(ParamT : const(UnqualParamT), UnqualParamT) // Allows ParamT to be "const(int)", "immutable(short)", etc. while giving us the unqualified version to select against (since annoying things like is(const(short) : int) is true).
    )
    {
        static assert(!__traits(isUnsigned, UnqualParamT), "unsigned integers aren't supported as Postgres itself only supports signed types"); // @suppress(dscanner.style.long_line)
        static assert(isText);
        
        static if(is(UnqualParamT == short))
            return encodeInt2Text(psql, param, psql.params);
        else static if(is(UnqualParamT == int))
            return encodeInt4Text(psql, param, psql.params);
        else static assert(false, "Don't know how to handle integral type "~ParamT.stringof);
    }
    else static if(is(ParamT : Duration))
    {
        static assert(isText);
        return encodeTimeText(psql, param, psql.params);
    }
    else static if(is(ParamT : PostgresTimetz))
    {
        static assert(isText);
        return encodeTimetzText(psql, param, psql.params);
    }
    else static if(is(ParamT : PostgresDate))
    {
        static assert(isText);
        return encodeDateText(psql, param, psql.params);
    }
    else static if(is(ParamT : PostgresTimestamp))
    {
        static assert(isText);
        return encodeTimestampText(psql, param, psql.params);
    }
    else static if(is(ParamT : PostgresTimestamptz))
    {
        static assert(isText);
        return encodeTimestamptzText(psql, param, psql.params);
    }
    else static assert(false, "Don't know how to convert D type "~ParamT.stringof~" into Postgres wire type");
}

private Result decodeResult(ResultT)(
    scope ref ResultT ret, 
    scope ref MemoryReader reader,
    scope PostgresColumnDescription.Format format,
    scope PostgresDataTypeOid type,
    scope ref const(PostgresParameters) params,
)
{
    import juptune.core.ds : String;
    import juptune.postgres.protocol.datatypes; // Intentionally imports everything.

    const isText = (format == PostgresColumnDescription.Format.text);

    static if(is(ResultT : const(char)[]) || is(ResultT == String))
    {
        const(char)[] slice;

        auto result = (isText)
            ? decodeTextText(reader, slice, params)
            : decodeTextBinary(reader, slice, params);

        if(!result.isError)
        {
            static if(is(ResultT : const(char)[]))
            {
                // When using native slices, our only safe option is to use the GC.
                // We can't give the raw slice back as it'll be overwritten on the next request, which is unsafe.
                ret = slice.idup;
            }
            else static if(is(ResultT : String))
            {
                ret = String(slice);
            }
            else static assert(false, "missing case");
        }

        return result;
    }
    else static if(is(ResultT : bool))
    {
        return (isText)
            ? decodeBooleanText(reader, ret, params)
            : decodeBooleanBinary(reader, ret, params);
    }
    else static if(
        __traits(isIntegral, ResultT) 
        && is(ResultT : const(UnqualResultT), UnqualResultT) // Allows ParamT to be "const(int)", "immutable(short)", etc. while giving us the unqualified version to select against (since annoying things like is(const(short) : int) is true).
    )
    {
        switch(type) with(PostgresDataTypeOid)
        {
            static if(is(UnqualResultT == short))
            {
                case int2:
                    return (isText)
                        ? decodeInt2Text(reader, ret, params)
                        : decodeInt2Binary(reader, ret, params);
            }
            else static if(is(UnqualResultT == int))
            {
                case int4:
                    return (isText)
                        ? decodeInt4Text(reader, ret, params)
                        : decodeInt4Binary(reader, ret, params);
            }

            default:
                assert(false, "bug: Missing integral case? Why did areCompatibleTypes pass?");
        }
    }
    else static if(is(ResultT : Duration))
    {
        return (isText)
            ? decodeTimeText(reader, ret, params)
            : decodeTimeBinary(reader, ret, params);
    }
    else static if(is(ResultT : PostgresTimetz))
    {
        return (isText)
            ? decodeTimetzText(reader, ret, params)
            : decodeTimetzBinary(reader, ret, params);
    }
    else static if(is(ResultT : PostgresDate))
    {
        return (isText)
            ? decodeDateText(reader, ret, params)
            : decodeDateBinary(reader, ret, params);
    }
    else static if(is(ResultT : PostgresTimestamp))
    {
        return (isText)
            ? decodeTimestampText(reader, ret, params)
            : decodeTimestampBinary(reader, ret, params);
    }
    else static if(is(ResultT : PostgresTimestamptz))
    {
        return (isText)
            ? decodeTimestamptzText(reader, ret, params)
            : decodeTimestamptzBinary(reader, ret, params);
    }
    else static assert(false, "Don't know how to convert D type "~ResultT.stringof~" into Postgres wire type");
}

private Result areCompatibleTypes(ParamT)(
    scope ref PostgresColumnDescription desc,
    scope out PostgresColumnDescription.Format format,
    scope out PostgresDataTypeOid type,
)
{
    import juptune.core.ds : String;

    format = desc.format;
    type = desc.dataType;

    const isText = (desc.format == PostgresColumnDescription.Format.text);

    static if(is(ParamT : const(char)[]) || is(ParamT : String))
    {
        // strings are compatible with every type's text format... since we can just pass through the raw text.
        if(isText)
            return Result.noError;

        // For binary formats, only certain types are compatible with being directly turned into strings.
        switch(desc.dataType) with(PostgresDataTypeOid)
        {
            case bpchar:
            case varchar:
            case text:
                return Result.noError;

            default:
                return Result.make(
                    PostgresClientError.typeMismatch,
                    "string D type "~ParamT.stringof~" is not compatible with Postgres wire type (binary format)",
                    String("Postgres data type was ", desc.dataType)
                );
        }
    }
    else static if(is(ParamT : bool))
    {
        if(desc.dataType != PostgresDataTypeOid.boolean)
        {
            return Result.make(
                PostgresClientError.typeMismatch,
                "boolean D type "~ParamT.stringof~" is not compatible with Postgres wire type",
                String("Postgres data type was ", desc.dataType)
            );
        }

        return Result.noError;
    }
    else static if(
        __traits(isIntegral, ParamT) 
        && is(ParamT : const(UnqualParamT), UnqualParamT) // Allows ParamT to be "const(int)", "immutable(short)", etc. while giving us the unqualified version to select against (since annoying things like is(const(short) : int) is true).
    )
    {
        static assert(!__traits(isUnsigned, UnqualParamT), "unsigned integers aren't supported as Postgres itself only supports signed types"); // @suppress(dscanner.style.long_line)

        switch(desc.dataType) with(PostgresDataTypeOid)
        {
            static if(is(UnqualParamT == short))
            {
                case int2: return Result.noError;
            }
            else static if(is(UnqualParamT == int))
            {
                case int4: return Result.noError;
            }

            default:
                return Result.make(
                    PostgresClientError.typeMismatch,
                    "integral D type "~ParamT.stringof~" is not compatible with Postgres wire type",
                    String("Postgres data type was ", desc.dataType)
                );
        }
    }
    else static if(is(ParamT : Duration))
    {
        if(desc.dataType != PostgresDataTypeOid.time)
        {
            return Result.make(
                PostgresClientError.typeMismatch,
                "time D type "~ParamT.stringof~" is not compatible with Postgres wire type",
                String("Postgres data type was ", desc.dataType)
            );
        }

        return Result.noError;
    }
    else static if(is(ParamT : PostgresTimetz))
    {
        if(desc.dataType != PostgresDataTypeOid.timetz)
        {
            return Result.make(
                PostgresClientError.typeMismatch,
                "timetz D type "~ParamT.stringof~" is not compatible with Postgres wire type",
                String("Postgres data type was ", desc.dataType)
            );
        }

        return Result.noError;
    }
    else static if(is(ParamT : PostgresDate))
    {
        if(desc.dataType != PostgresDataTypeOid.date)
        {
            return Result.make(
                PostgresClientError.typeMismatch,
                "date D type "~ParamT.stringof~" is not compatible with Postgres wire type",
                String("Postgres data type was ", desc.dataType)
            );
        }

        return Result.noError;
    }
    else static if(is(ParamT : PostgresTimestamp))
    {
        if(desc.dataType != PostgresDataTypeOid.timestamp)
        {
            return Result.make(
                PostgresClientError.typeMismatch,
                "timestamp D type "~ParamT.stringof~" is not compatible with Postgres wire type",
                String("Postgres data type was ", desc.dataType)
            );
        }

        return Result.noError;
    }
    else static if(is(ParamT : PostgresTimestamptz))
    {
        if(desc.dataType != PostgresDataTypeOid.timestamptz)
        {
            return Result.make(
                PostgresClientError.typeMismatch,
                "timestamptz D type "~ParamT.stringof~" is not compatible with Postgres wire type",
                String("Postgres data type was ", desc.dataType)
            );
        }

        return Result.noError;
    }
    else static assert(false, "Don't know how to compare D type "~ParamT.stringof~" against Postgres wire type");
}