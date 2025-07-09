/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

const MAIN_HELP = 
`Commands:
    compile dlang-raw   - TODO
    print               - Parses ASN.1 notation files, and prints out how dasn1 interpreted each file.
`;

int main(string[] args)
{
    import std.stdio : writeln;

    if(args.length == 1)
    {
        writeln("error: no arguments provided\n");
        writeln(MAIN_HELP);
        return 1;
    }

    try
    {    
        switch(args[1])
        {
            case "print":
                import dasn1.print : printCommand;
                return printCommand(args[1..$]);

            case "compile":
                if(args.length == 2)
                {
                    writeln("error: `compile` is not a command, please specify the language-type pair e.g. `compile dlang-raw`\n"); // @suppress(dscanner.style.long_line)
                    writeln(MAIN_HELP);
                    return 1;
                }

                switch(args[2])
                {
                    case "dlang-raw":
                        import dasn1.compile : compileDlangRawCommand;
                        return compileDlangRawCommand(args[2..$]);

                    default:
                        writeln("error: `dlang-raw` is not a valid language-type pair.\n");
                        writeln(MAIN_HELP);
                        return 1;
                }

            default:
                writeln("error: invalid command '", args[1], "'\n");
                writeln(MAIN_HELP);
                return 1;
        }
    }
    catch(Exception ex)
    {
        writeln("Warning: Unhandled exception\n\n", ex.msg);
        debug writeln(" ========= DEBUG ======== \n\n", ex);
        return 1;
    }
}