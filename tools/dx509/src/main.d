/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

const MAIN_HELP = 
`Commands:
    x509 print <pemfile> - Parses all certificates in the given PEM file and prints out a bunch of info about them.
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
            case "x509":
                if(args.length == 2)
                {
                    writeln("error: `x509` is not a command, please specify an additional subcommand, e.g. `x509 print`\n"); // @suppress(dscanner.style.long_line)
                    writeln(MAIN_HELP);
                    return 1;
                }

                switch(args[2])
                {
                    case "hexdump":
                        import dx509.x509_hexdump : onX509HexDumpCommand;
                        return onX509HexDumpCommand(args[3..$]);

                    case "print":
                        import dx509.x509_print : onX509PrintCommand;
                        return onX509PrintCommand(args[3..$]);

                    default:
                        writeln("error: `", args[2], "` is not a valid x509 subcommand.\n");
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