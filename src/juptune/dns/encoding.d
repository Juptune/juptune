module juptune.dns.encoding;

import juptune.core.util    : Result;
import juptune.data.buffer  : MemoryWriter, MemoryReader;
import juptune.dns.types    : DnsHeaderOpcode, DnsRecordClass, DnsRecordType, DnsResponseCode;

/++
 + The max length of a label - where a label is a segment/subdomain within a wider domain name.
 +
 + Specs:
 +  RFC1035 2.3.4
 + ++/
enum DNS_MAX_LABEL_LENGTH = 63;

/++
 + The max length of a domain name in total, including the dots.
 +
 + Specs:
 +  RFC1035 2.3.4
 + ++/
enum DNS_MAX_DOMAIN_LENGTH = 255; // NOTE: Every label adds a +1 overhead for its length byte, which gets included in this limit

/// A `Result` error enum
enum DnsEncodingError
{
    none,

    /// A label (segment of a domain name) was too long.
    labelTooLong,

    /// The domain name was too long in total.
    domainNameTooLong,

    /// A label (segment of a domain name) was invalid for some reason.
    invalidLabel,

    /// When encoding into a buffer, the end of the buffer was reached before finishing the encoding.
    bufferTooSmall,

    /// When decoding, the end of the buffer was reached prematurely.
    eof,

    /// When decoding, there were bytes left in the buffer that weren't used.
    trailingData,
}

/++++ Encoders ++++/

/++
 + Provided by `dnsEncodeQuery` to the caller's `putQuestions` function. Allows the caller to
 + add an entry into the questions section of a DNS query.
 +
 + Params:
 +  domainName  = The domain name to query, e.g. "google.com".
 +  recordType  = The type of records to fetch for the domain.
 +  recordClass = The class of records to fetch for the domain (`DnsRecordClass.in_` 99% of the time).
 +
 + Throws:
 +  `DnsEncodingError.bufferTooSmall` if the write buffer is too small to fit the encoded question.
 +
 +  Anything `dnsSplitDomainName` can throw.
 +
 + Returns:
 +  A `Result`
 + ++/
alias DnsPutQuestionFunc = Result delegate(
    scope const(char)[] domainName,
    DnsRecordType       recordType,
    DnsRecordClass      recordClass,
) @nogc nothrow;

/++
 + Provided by `dnsEncodeQuery` to the caller's `putAdditionalRecords` function. Allows the caller to
 + add an entry into the additional records section of a DNS query.
 +
 + Notes:
 +  This function can be called multiple times. Each time it is called, the previous call's record is automatically finalised.
 +
 +  Since the `recordType` and `recordClass` fields can be interpreted in special ways (e.g. for the OPT pseduo-RR), they're
 +  typed as raw ushorts rather than something more concrete.
 +
 +  If `rbodyWriter` fails to write data, it's recommended to return a result of `DnsEncodingError.bufferTooSmall`.
 +
 + Params:
 +  domainName  = The domain name to query, e.g. "google.com".
 +  recordType  = The type of the additional record.
 +  recordClass = The class of the additional record.
 +  ttl         = The TTL of the additional record.
 +  rbodyWriter = An output `MemoryWriter*` that the caller can use to populate the record's rbody. It goes without saying, but DO NOT escape this pointer.
 +
 + Throws:
 +  `DnsEncodingError.bufferTooSmall` if the write buffer is too small to fit the encoded record.
 +
 +  Anything `dnsSplitDomainName` can throw.
 +
 + Returns:
 +  A `Result`
 + ++/
alias DnsStartNextRecordFunc = Result delegate(
    // (Some records - especially in the additional records section - have wide interpretations for certain fields, so things like recordType are more openly typed).
    scope const(char)[]     domainName,
    ushort                  recordType,
    ushort                  recordClass,
    uint                    ttl,
    scope out MemoryWriter* rbodyWriter,
) @nogc nothrow;

/++
 + Encodes a DNS query into the on-the-wire format initially described in RFC1035.
 +
 + Notes:
 +  This is a low-level function that generally doesn't need to be called by itself, please use the higher level stuff
 +  such as TODO.
 +
 +  If this function throws an error, the contents of `writer` is undefined.
 +
 + Params:
 +  id                      = A user-defined ID for the record. The server will include this ID in its response.
 +  writer                  = A `MemoryWriter` used for writing the encoded payload into a caller-controlled buffer.
 +  putQuestions            = A callback that allows the caller to put an arbitrary amount of questions into the query.
 +  putAdditionalRecords    = A callback that allows the caller to put an arbtirary amount of additional records into the query (e.g. for EDNS).
 +  opcode                  = The opcode of the query.
 +
 + Throws:
 +  `DnsEncodingError.bufferTooSmall` if the write buffer is too small to fit the encoded record.
 +
 +  Anything that `putQuestions` (and `DnsPutQuestionFunc` by association) can throw.
 +
 +  Anything that `putAdditionalRecords` (and `DnsStartNextRecordFunc` by association) can throw.
 + ++/
alias dnsEncodeQuery = dnsEncodeQueryImpl!(
    Result delegate(scope DnsPutQuestionFunc putQuestion) @nogc nothrow,
    Result delegate(scope DnsStartNextRecordFunc startNextRecord) @nogc nothrow,
);

/// ditto
alias dnsEncodeQueryGc = dnsEncodeQueryImpl!(
    Result delegate(scope DnsPutQuestionFunc putQuestion),
    Result delegate(scope DnsStartNextRecordFunc startNextRecord),
);

private Result dnsEncodeQueryImpl(PutQuestionsFuncT, PutAdditionalFuncT)(
    ushort                      id,
    scope ref MemoryWriter      writer,
    scope PutQuestionsFuncT     putQuestions,
    scope PutAdditionalFuncT    putAdditionalRecords,
    DnsHeaderOpcode             opcode = DnsHeaderOpcode.query,
)
in(putQuestions !is null, "bug: putQuestions is null")
in(putAdditionalRecords !is null, "bug: putAdditionalRecords is null")
{
    /++++ Setup header (4.1.1) ++++/

    // (God I hope the compiler optimises this properly)
    const bytes2And3 = cast(ushort)(
        (0 << 15)                   // QR of 0
        | ((opcode & 0b1111) << 14) // Opcode
        | (0 << 10)                 // AA of 0
        | (0 << 9)                  // TC of 0
        | (1 << 8)                  // RD of 1
        | (0 << 7)                  // RA of 0
        | (0b000 << 4)              // "Z" of 0
        | (0b0000)                  // RCODE of 0
    );

    MemoryWriter qdCountWriter;
    MemoryWriter arCountWriter;

    ushort qdCount;
    ushort arCount;

    auto couldWrite = writer.putU16BE(id);
    couldWrite      = couldWrite && writer.putU16BE(bytes2And3);
    couldWrite      = couldWrite && writer.putU16BE(ushort.max); // QDCOUNT temp value
    qdCountWriter   = couldWrite ? MemoryWriter(writer.usedBuffer[$-2..$]) : MemoryWriter.init;
    couldWrite      = couldWrite && writer.putU16BE(0);          // ANCOUNT temp value
    couldWrite      = couldWrite && writer.putU16BE(0);          // NSCOUNT temp value
    couldWrite      = couldWrite && writer.putU16BE(ushort.max); // ARCOUNT temp value
    arCountWriter   = couldWrite ? MemoryWriter(writer.usedBuffer[$-2..$]) : MemoryWriter.init;
    if(!couldWrite)
        return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding header"); // @suppress(dscanner.style.long_line)

    /++++ Let the caller write as many questions as they want ++++/

    scope DnsPutQuestionFunc putQuestionsCallback = (scope const domainName, recordType, recordClass){
        qdCount++;

        /++ Write the labels ++/
        auto result = dnsSplitDomainName(domainName, onLabel: (scope const label){
            assert(label.length <= DNS_MAX_LABEL_LENGTH, "failsafe: why didn't dnsSplitDomainName catch this?");
            
            auto couldWriteLabel = writer.putI8(cast(byte)label.length & 0b0011_1111);
            couldWriteLabel      = couldWriteLabel && writer.tryBytes(cast(ubyte[])label);
            if(!couldWriteLabel)
                return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding domain label of domain name in a question"); // @suppress(dscanner.style.long_line)

            return Result.noError;
        });
        if(result.isError)
            return result;

        const couldWriteNullLength = writer.putI8(0); // Put the "null" label
        if(!couldWriteNullLength)
            return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding null label of in a question"); // @suppress(dscanner.style.long_line)

        /++ Then the type and class ++/
        auto couldFinishQuestion = writer.putU16BE(recordType);
        couldFinishQuestion      = couldFinishQuestion && writer.putU16BE(recordClass);
        if(!couldFinishQuestion)
            return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding type and class of question"); // @suppress(dscanner.style.long_line)

        return Result.noError;
    };

    auto result = putQuestions(putQuestionsCallback);
    if(result.isError)
        return result;

    // Update the count field
    const couldWriteQdCount = qdCountWriter.putU16BE(qdCount);
    assert(couldWriteQdCount, "bug: failed to write QDCOUNT?");

    /++ Do the same for additional records ++/

    MemoryWriter rdataWriter;
    MemoryWriter rdlengthWriter;

    void flushRdLength()
    {
        if(rdlengthWriter == MemoryWriter.init)
            return;

        assert(rdataWriter.usedBuffer.length <= ushort.max, "bug: rdataWriter wrote too much data?");
        rdlengthWriter.putU16BE(cast(ushort)rdataWriter.usedBuffer.length);
        writer.goForward(rdataWriter.usedBuffer.length);
        rdataWriter    = MemoryWriter.init;
        rdlengthWriter = MemoryWriter.init;
    }

    scope DnsStartNextRecordFunc startNextRecord = (
        scope const domainName, 
        recordType, 
        recordClass, 
        ttl, 
        scope out rbodyWriter
    ){
        // Flush the previous record
        if(arCount > 0)
            flushRdLength();

        // TODO: The start of non-question records is the exact same as a question record, so this should be DRYed
        arCount++;

        /++ Write the labels ++/
        auto result = dnsSplitDomainName(domainName, onLabel: (scope const label){
            assert(label.length <= DNS_MAX_LABEL_LENGTH, "failsafe: why didn't dnsSplitDomainName catch this?");
            
            auto couldWriteLabel = writer.putI8(cast(byte)label.length & 0b0011_1111);
            couldWriteLabel      = couldWriteLabel && writer.tryBytes(cast(ubyte[])label);
            if(!couldWriteLabel)
                return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding domain label of domain name in an additional record"); // @suppress(dscanner.style.long_line)

            return Result.noError;
        });
        if(result.isError)
            return result;

        const couldWriteNullLength = writer.putI8(0); // Put the "null" label
        if(!couldWriteNullLength)
            return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding null label of in an additional record"); // @suppress(dscanner.style.long_line)

        /++ Then the type, class, and TTL ++/
        auto couldFinishHeader = writer.putU16BE(recordType);
        couldFinishHeader      = couldFinishHeader && writer.putU16BE(recordClass);
        couldFinishHeader      = couldFinishHeader && writer.putU32BE(ttl);
        if(!couldFinishHeader)
            return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding type, class, and TTL of an additional record"); // @suppress(dscanner.style.long_line)

        /++ Set a dummy value for RDLENGTH, then return control to the caller so it can start writing ++/
        const couldWriteRdLength = writer.putU16BE(ushort.max);
        if(!couldWriteRdLength)
            return Result.make(DnsEncodingError.bufferTooSmall, "when encoding a query, ran out of buffer space when encoding RDLENGTH of an additional record"); // @suppress(dscanner.style.long_line)

        rdlengthWriter = MemoryWriter(writer.usedBuffer[$-2..$]);
        rdataWriter    = MemoryWriter(writer.buffer[writer.cursor..$]); // (unused parts of the buffer)
        rbodyWriter    = &rdataWriter;

        return Result.noError;
    };

    result = putAdditionalRecords(startNextRecord);
    if(result.isError)
        return result;
    flushRdLength();

    // Update the count field
    const couldWriteArCount = arCountWriter.putU16BE(arCount);
    assert(couldWriteArCount, "bug: failed to write ARCOUNT?");

    return Result.noError;
}

// unittest
// {
//     import juptune.event.io : UdpSocket;
//     import juptune.core.util : resultAssert;
//     import juptune.event;

//     import std.exception;
//     import std.typecons;
//     import std.file : readText;

//     auto loop = EventLoop(EventLoopConfig());
//     loop.addGCThread((){
//         import juptune.http;

//         IpAddress ip;
//         IpAddress.parse(ip, "1.1.1.1", 53).resultAssert;

//         import juptune.dns.clients.rfc1035 : dnsQueryRfc1035, DnsRfc1035QueryConfig;
//         import juptune.dns.types : DnsQuery;

//         size_t used;
//         dnsQueryRfc1035(ip, DnsQuery("google.com", DnsRecordType.a), new ubyte[5000], used).resultAssert;
//     });
//     loop.join();
// }

/++++ Decoders ++++/

struct DnsDecodedHeader
{
    ushort          id;
    bool            isResponse; // false = is a query
    DnsHeaderOpcode opcode;
    bool            isAuthoritative;
    bool            wasTruncated;
    bool            recursionDesired;
    bool            recursionAvailable;
    bool            z0;
    bool            z1;
    bool            z2;
    DnsResponseCode rcode;
    ushort          questionCount;
    ushort          answerCount;
    ushort          authorityCount;
    ushort          additionalCount;
}

struct DnsDecodedQuestion
{
    const(char)[]   domainNameDoNotEscape; // (backed by a stack array)
    ushort          recordType;  // (ushort for easier decoding)
    ushort          recordClass; // (ushort for easier decoding)
}

struct DnsDecodedRecord
{
    const(char)[]   domainNameDoNotEscape; // (backed by a stack array)
    ushort          recordType;  // (ushort for easier decoding, and since this isn't always a DnsRecordType)
    ushort          recordClass; // (ushort for easier decoding, and since this isn't always a DnsRecordClass)
    uint            ttl;
    const(ubyte)[]  rdata; // (backed by the input array)
}

/++
 + Decodes a DNS on-the-wire payload, passing each part into caller-provided callbacks.
 +
 + Notes:
 +  Please - for the love of dogs - do not escape any of the `domainNameDoNotEscape` fields. These are stack allocated! Copy them instead!
 +
 +  This is a low-level function that generally doesn't need to be called by itself, please use the higher level stuff
 +  such as TODO.
 +
 +  This function does not automatically throw if the payload contains an error code.
 +
 +  If this function throws then the state of `reader` is undefined.
 +
 + Params:
 +  reader          = A `MemoryReader` that's been setup to read an on-the-wire payload from a caller controlled buffer.
 +  onHeader        = A callback (called only once) that's used when the header of the payload is decoded.
 +  onQuestion      = A callback that's called each time a question record is decoded.
 +  onAnswer        = A callback that's called each time an answer record is decoded.
 +  onAuthority     = A callback that's called each time an authority record is decoded.
 +  onAdditional    = A callback that's called each time an additional record is decoded.
 +
 + Throws:
 +  `DnsEncodingError.eof` if the end of `reader` is unexpectedly reached.
 +
 +  `DnsEncodingError.domainNameTooLong` if a decoded domain name is longer than DNS_MAX_DOMAIN_LENGTH.
 +
 +  `DnsEncodingError.invalidLabel` for various reasons.
 +
 +  `DnsEncodingError.trailingData` if the payload is fully decoded, but `reader` still has bytes left that weren't read in.
 +
 +  Anything `dnsSplitDomainName` can throw.
 +
 +  Anything that any of the callback functions can throw.
 + ++/
alias dnsDecodePayload = dnsDecodePayloadImpl!(
    /* OnHeaderFuncT        */ Result delegate(scope DnsDecodedHeader header) @nogc nothrow,
    /* OnQuestionFuncT      */ Result delegate(scope DnsDecodedQuestion question) @nogc nothrow,
    /* OnAnswerFuncT        */ Result delegate(scope DnsDecodedRecord record) @nogc nothrow,
    /* OnAuthorityFuncT     */ Result delegate(scope DnsDecodedRecord record) @nogc nothrow,
    /* OnAdditionalFuncT    */ Result delegate(scope DnsDecodedRecord record) @nogc nothrow,
);

/// ditto
alias dnsDecodePayloadGc = dnsDecodePayloadImpl!(
    /* OnHeaderFuncT        */ Result delegate(scope DnsDecodedHeader header),
    /* OnQuestionFuncT      */ Result delegate(scope DnsDecodedQuestion question),
    /* OnAnswerFuncT        */ Result delegate(scope DnsDecodedRecord record),
    /* OnAuthorityFuncT     */ Result delegate(scope DnsDecodedRecord record),
    /* OnAdditionalFuncT    */ Result delegate(scope DnsDecodedRecord record),
);

private Result dnsDecodePayloadImpl(
    OnHeaderFuncT, 
    OnQuestionFuncT, 
    OnAnswerFuncT,
    OnAuthorityFuncT,
    OnAdditionalFuncT,
)(
    scope ref MemoryReader  reader,
    scope OnHeaderFuncT     onHeader,
    scope OnQuestionFuncT   onQuestion,
    scope OnAnswerFuncT     onAnswer,
    scope OnAuthorityFuncT  onAuthority,
    scope OnAdditionalFuncT onAdditional,
)
in(onHeader !is null, "bug: onHeader is null")
in(onQuestion !is null, "bug: onQuestion is null")
in(onAnswer !is null, "bug: onAnswer is null")
in(onAuthority !is null, "bug: onAuthority is null")
in(onAdditional !is null, "bug: onAdditional is null")
{
    DnsDecodedHeader header;

    char[DNS_MAX_DOMAIN_LENGTH] domainName;

    Result decodeLabelsIntoBuffer(scope out const(char)[] usedDomainNameSlice)
    {
        size_t domainNameCursor;

        MemoryReader pointerReader;
        MemoryReader* readerInUse = &reader;

        auto startOfDomainName = reader.cursor;

        while(true)
        {
            if(readerInUse.bytesLeft == 0)
                return Result.make(DnsEncodingError.eof, "when decoding domain name, reached end of buffer before finding null label"); // @suppress(dscanner.style.long_line)

            ubyte labelPrefix;
            const couldReadLength = readerInUse.readU8(labelPrefix);
            if(!couldReadLength)
                return Result.make(DnsEncodingError.eof, "when decoding length of label, reached end of buffer");

            const labelType   = (0b1100_0000 & labelPrefix) >> 6;
            const labelLength = (0b0011_1111 & labelPrefix);

            if(labelType == 0b00) // Normal label
            {
                if(labelLength == 0) // We've hit the end label
                    break;

                if(domainNameCursor + labelLength + 1 > domainName.length)
                    return Result.make(DnsEncodingError.domainNameTooLong, "when decoding domain name, name exceeded max length"); // @suppress(dscanner.style.long_line)

                const(ubyte)[] label;
                const couldReadLabel = readerInUse.readBytes(labelLength, label);
                if(!couldReadLabel)
                    return Result.make(DnsEncodingError.eof, "when decoding normal label, reached end of buffer");

                if(domainNameCursor != 0)
                    domainName[domainNameCursor++] = '.';
                domainName[domainNameCursor..domainNameCursor + label.length] = cast(char[])label;
                domainNameCursor += label.length;
            }
            else if(labelType == 0b11) // Pointer label
            {
                ubyte pointerByte2;
                const couldReadPointerByte = readerInUse.readU8(pointerByte2);
                if(!couldReadPointerByte)
                    return Result.make(DnsEncodingError.eof, "when decoding pointer label, reached end of buffer when expecting second pointer byte"); // @suppress(dscanner.style.long_line)

                const pointerToLabel = (labelLength << 8) | pointerByte2;

                if(pointerToLabel >= startOfDomainName)
                    return Result.make(DnsEncodingError.invalidLabel, "when decoding pointer label, pointer doesn't refer to a previous label, but instead a future/the current label"); // @suppress(dscanner.style.long_line)

                pointerReader     = MemoryReader(reader.buffer, pointerToLabel);
                readerInUse       = &pointerReader;
                startOfDomainName = pointerToLabel;
            }
            else
                return Result.make(DnsEncodingError.invalidLabel, "when decoding domain name, encountered label with unknown type"); // @suppress(dscanner.style.long_line)
        }

        usedDomainNameSlice = domainName[0..domainNameCursor];
        
        // (This is just for the validation this function provides)
        return dnsSplitDomainName(usedDomainNameSlice, (_) => Result.noError);
    }

    /++++ Decode the header ++++/
    const(ubyte)[] headerBytes2And3;

    auto couldReadHeader = reader.readU16BE(header.id);
    couldReadHeader      = reader.readBytes(2, headerBytes2And3);
    couldReadHeader      = reader.readU16BE(header.questionCount);
    couldReadHeader      = reader.readU16BE(header.answerCount);
    couldReadHeader      = reader.readU16BE(header.authorityCount);
    couldReadHeader      = reader.readU16BE(header.additionalCount);
    if(!couldReadHeader)
        return Result.make(DnsEncodingError.eof, "when decoding header, hit EoF unexpectedly");

    header.isResponse           = cast(bool)(0b1000_0000 & headerBytes2And3[0]);
    header.opcode               = cast(DnsHeaderOpcode)(0b0111_1000 & headerBytes2And3[0]);
    header.isAuthoritative      = cast(bool)(0b0000_0100 & headerBytes2And3[0]);
    header.wasTruncated         = cast(bool)(0b0000_0010 & headerBytes2And3[0]);
    header.recursionDesired     = cast(bool)(0b0000_0001 & headerBytes2And3[0]);
    header.recursionAvailable   = cast(bool)(0b1000_0000 & headerBytes2And3[1]);
    header.z0                   = cast(bool)(0b0100_0000 & headerBytes2And3[1]);
    header.z1                   = cast(bool)(0b0010_0000 & headerBytes2And3[1]);
    header.z2                   = cast(bool)(0b0001_0000 & headerBytes2And3[1]);
    header.rcode                = cast(DnsResponseCode)(0b0000_1111 & headerBytes2And3[1]);

    auto result = onHeader(header);
    if(result.isError)
        return result;

    /++++ Decode questions ++++/
    foreach(i; 0..header.questionCount)
    {
        DnsDecodedQuestion question;

        result = decodeLabelsIntoBuffer(question.domainNameDoNotEscape);
        if(result.isError)
            return result;

        auto couldRead = reader.readU16BE(question.recordType);
        couldRead      = reader.readU16BE(question.recordClass);
        if(!couldRead)
            return Result.make(DnsEncodingError.eof, "when decoding question, hit end of buffer when reading record type and class"); // @suppress(dscanner.style.long_line)

        result = onQuestion(question);
        if(result.isError)
            return result;
    }

    /++++ Decode the other record sections ++++/
    Result decodeRecords(OnRecordFuncT)(ushort count, scope OnRecordFuncT onRecord)
    {
        foreach(_; 0..count)
        {
            DnsDecodedRecord record;
            ushort rdlength;

            result = decodeLabelsIntoBuffer(record.domainNameDoNotEscape);
            if(result.isError)
                return result;

            auto couldRead = reader.readU16BE(record.recordType);
            couldRead      = reader.readU16BE(record.recordClass);
            couldRead      = reader.readU32BE(record.ttl);
            couldRead      = reader.readU16BE(rdlength);
            if(!couldRead)
                return Result.make(DnsEncodingError.eof, "when decoding record, hit end of buffer when reading record type, class, ttl, and rdlength"); // @suppress(dscanner.style.long_line)

            const couldReadRdata = reader.readBytes(rdlength, record.rdata);
            if(!couldReadRdata)
                return Result.make(DnsEncodingError.eof, "when decoding record, hit end of buffer when reading rdata"); // @suppress(dscanner.style.long_line)

            result = onRecord(record);
            if(result.isError)
                return result;
        }

        return Result.noError;
    }

    result = decodeRecords(header.answerCount, onAnswer);
    if(result.isError)
        return result;
    result = decodeRecords(header.authorityCount, onAuthority);
    if(result.isError)
        return result;
    result = decodeRecords(header.additionalCount, onAdditional);
    if(result.isError)
        return result;

    if(reader.bytesLeft > 0)
        return Result.make(DnsEncodingError.trailingData, "when decoding payload, there were leftover bytes that weren't decoded"); // @suppress(dscanner.style.long_line)

    return Result.noError;
}

/++++ Helpers ++++/

/++
 + Splits a domain name into labels. e.g. "abc.def.com" -> ["abc", "def", "com"].
 +
 + Notes:
 +  This also performs validation to ensure that the domain name is valid for DNS.
 +
 + Params:
 +  domainName = The domain name to split.
 +  onLabel    = Called each time a label is split. The provided label is a direct slice of `domainName`.
 +
 + Throws:
 +  `DnsEncodingError.invalidLabel` for various reasons.
 +
 +  `DnsEncodingError.labelTooLong` if a label is longer than `DNS_MAX_LABEL_LENGTH`.
 +
 +  `DnsEncodingError.domainNameTooLong` if the entire domain name is longer than `DNS_MAX_DOMAIN_LENGTH`.
 +
 + Returns:
 +  A `Result`
 + ++/
alias dnsSplitDomainName = dnsSplitDomainNameImpl!(Result delegate(scope const(char)[] label) @nogc nothrow);

/// ditto
alias dnsSplitDomainNameGc = dnsSplitDomainNameImpl!(Result delegate(scope const(char)[] label));

private Result dnsSplitDomainNameImpl(HandlerT)(scope const(char)[] domainName, scope HandlerT onLabel)
{
    uint labelLengthSum = 0;
    size_t startOfLabel = 0;
    size_t cursor = 0;
    while(cursor < domainName.length)
    {
        /++++ Validate that the character is allowed ++++/
        const ch = domainName[cursor];
        const isLower   = (ch >= 'a' && ch <= 'z');
        const isUpper   = (ch >= 'A' && ch <= 'Z');
        const isNumeric = (ch >= '0' && ch <= '9');
        const isHyphen  = (ch == '-');
        const isDot     = (ch == '.');

        if(!isLower && !isUpper && !isNumeric && !isHyphen && !isDot)
            return Result.make(DnsEncodingError.invalidLabel, "when splitting domain name into labels, encountered a label that was not alphanumeric or an infix hyphen"); // @suppress(dscanner.style.long_line)

        if(isHyphen && startOfLabel == cursor)
            return Result.make(DnsEncodingError.invalidLabel, "when splitting domain name into labels, encountered a label that started with a hyphen"); // @suppress(dscanner.style.long_line)
        else if(isHyphen && (cursor + 1 == domainName.length || domainName[cursor + 1] == '.'))
            return Result.make(DnsEncodingError.invalidLabel, "when splitting domain name into labels, encountered a label that ended with a hyphen"); // @suppress(dscanner.style.long_line)

        /++++ Split on dots and handle when we've hit the end of the input ++++/
        if(cursor == domainName.length - 1 || ch == '.') // @suppress(dscanner.suspicious.length_subtraction)
        {
            const end = (ch == '.') ? cursor : cursor + 1;
            const label = domainName[startOfLabel..end];
            if(label.length > DNS_MAX_LABEL_LENGTH)
                return Result.make(DnsEncodingError.labelTooLong, "when splitting domain name into labels, encountered a label that was longer than 63 characters"); // @suppress(dscanner.style.long_line)

            labelLengthSum += label.length + 1; // + 1 to account for the length byte once encoded
            if(labelLengthSum > DNS_MAX_DOMAIN_LENGTH)
                return Result.make(DnsEncodingError.domainNameTooLong, "when splitting domain name into labels, sum of labels and their overhead bytes exceeded 255 byte limit"); // @suppress(dscanner.style.long_line)

            auto result = onLabel(label);
            if(result.isError)
                return result;

            cursor++;
            startOfLabel = cursor;
        }
        else
            cursor++;
    }

    return Result.noError;
}