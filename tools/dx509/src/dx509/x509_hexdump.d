/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dx509.x509_hexdump;

int onX509HexDumpCommand(string[] args)
{
    import std.array        : Appender;
    import std.exception    : enforce;
    import std.format       : format;
    import std.getopt       : getopt, defaultGetoptPrinter;
    import std.stdio        : writef, writeln;
    import std.file         : readText;

    import juptune.core.util : Result, resultEnforce;

    import juptune.data.pem : PemParser;

    enum HELP_TEXT = "dx509 x509 hexdump [flags] <filename>";

    // Call getopt to deal with flags (and also the shitty interface requiring the first value to basically be ignored)
    args = ["_"] ~ args;
    auto argsResult = getopt(
        args,
    );
    args = args[1..$];

    if(argsResult.helpWanted)
    {
        defaultGetoptPrinter(HELP_TEXT, argsResult.options);
        return 0;
    }

    // Make sure the <filename> arg actually exists
    if(args.length == 0)
    {
        defaultGetoptPrinter(HELP_TEXT, argsResult.options);
        writeln("ERROR: missing <filename> argument");
        return 1;
    }

    if(args.length != 1)
    {
        defaultGetoptPrinter(HELP_TEXT, argsResult.options);
        writeln("ERROR: too many free-standing arguments, expected 1 but got ", args.length);
        return 1;
    }

    // Actually perform the command
    const filenameArg = args[0];
    const pem = readText(filenameArg);

    uint i;
    Appender!(ubyte[]) buffer;
    auto parser = PemParser(pem);
    while(!parser.eof)
    {
        // We're not using x509FromPem since we just want the bytes without parsing.
        parser.parseNextGC(
            onStart: (label){
                enforce(label == "CERTIFICATE", format("expected data boundary in PEM to have label CERTIFICATE, got label '%s' instead", label)); // @suppress(dscanner.style.long_line)
                return Result.noError; 
            },
            onData: (scope data){
                buffer.put(data);
                return Result.noError; 
            },
            onEnd: (){
                writef("---\n%d:\n[             /* 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F */", i); // @suppress(dscanner.style.long_line)

                foreach(i, byte_; buffer.data)
                {
                    if(i == 0 || (i % 0x10) == 0)
                        writef("\n    /* 0x%04X */ ", cast(uint)i);
                    writef("0x%02X, ", byte_);
                }

                writef("\n]\n");
                buffer.clear();
                return Result.noError;
            },
        ).resultEnforce;

        i++;
    }

    return 0;
}