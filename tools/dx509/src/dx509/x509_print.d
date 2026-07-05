/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module dx509.x509_print;

import juptune.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Name;

int onX509PrintCommand(string[] args)
{
    import std.array  : Appender;
    import std.getopt : getopt, defaultGetoptPrinter;
    import std.stdio  : writeln, writefln;
    import std.file   : readText;

    import juptune.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Certificate;

    import juptune.core.util : Result, resultEnforce;

    import juptune.data.x509.asn1convert    : X509Certificate, X509Extension, x509FromPemGC;
    import juptune.data.x509.store          : X509ExtensionStore;

    enum HELP_TEXT = "dx509 x509 print [flags] <filename>";

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

    uint certIndex;
    Appender!(ubyte[]) buffer;
    x509FromPemGC(
        pem,
        onPutBytes: (scope bytes) { 
            buffer.put(bytes); 
            return Result.noError;
        },
        onFinishBytes: (scope out bytes) {
            bytes = buffer.data; // We're not preserving certificates between calls, so we don't need to idup this
            buffer.clear();
            return Result.noError;
        },
        onCertificate: (Certificate _, X509Certificate x509Cert) {
            X509ExtensionStore extensions;
            X509ExtensionStore.fromCertificate(x509Cert, extensions).resultEnforce;

            if(certIndex != 0)
                writeln();

            writefln("Certificate #%d:", certIndex++);
            writefln("    General:");
            writefln("        Version   : %s", x509Cert.version_);
            writefln("        Serial    : %s", x509Cert.serialNumber.rawBytes.toHexString);
            writefln("    Signature:");
            writefln("        Algorithm : %s", x509Cert.signatureAlgorithm);
            writefln("        Value Bits: %s", x509Cert.signatureValue.bitCount);
            writefln("        Value     : %s", x509Cert.signatureValue.bytes.toHexString);
            writefln("    Validity:");
            writefln("        Not Before: %s", x509Cert.notValidBefore);
            writefln("        Not After : %s", x509Cert.notValidAfter);
            writefln("    Issuer:");
            writefln("        Unique ID: %s", x509Cert.issuerUniqueId);
            writefln("        Name:\n%s", toString(x509Cert.issuer, "            "));
            writefln("    Subject:");
            writefln("        Unique ID: %s", x509Cert.subjectUniqueId);
            writefln("        Name:\n%s", toString(x509Cert.subject, "            "));

            // This is intentionally jank, since this function's for special cases like this
            import std.traits : Parameters, TemplateArgsOf;
            Parameters!(X509ExtensionStore.getKnownExtensions) exts;
            extensions.getKnownExtensions(exts);

            foreach(ext; exts) // NOTE: This is a compile-time tuple foreach
            {
                if(ext.isNull)
                    continue;

                import std.traits : fullyQualifiedName;
                alias ExtType = TemplateArgsOf!(typeof(ext))[0];
                enum ExtTypeName = __traits(identifier, ExtType);
                writefln("    Extension %s:", ExtTypeName);

                static if(is(ExtType == X509Extension.SubjectKeyIdentifier))
                {
                    writefln("        ID: %s", ext.get.keyIdentifier.toHexString);
                }
                else static if(is(ExtType == X509Extension.AuthorityKeyIdentifier))
                {
                    writefln("        ID: %s", ext.get.keyIdentifier.toHexString);
                }
                else static if(is(ExtType == X509Extension.KeyUsage))
                {
                    writefln("        digitalSignature  : %s", ext.get.digitalSignature);
                    writefln("        contentCommitment : %s", ext.get.contentCommitment);
                    writefln("        keyEncipherment   : %s", ext.get.keyEncipherment);
                    writefln("        dataEncipherment  : %s", ext.get.dataEncipherment);
                    writefln("        keyAgreement      : %s", ext.get.keyAgreement);
                    writefln("        keyCertSign       : %s", ext.get.keyCertSign);
                    writefln("        cRLSign           : %s", ext.get.cRLSign);
                    writefln("        encipherOnly      : %s", ext.get.encipherOnly);
                    writefln("        decipherOnly      : %s", ext.get.decipherOnly);
                }
                else static if(is(ExtType == X509Extension.BasicConstraints))
                {
                    writefln("        CA            : %s", ext.get.ca);
                    writefln("        Path Length   : %s", ext.get.pathLenConstraint);
                }
                else static if(is(ExtType == X509Extension.ExtendedKeyUsage))
                {
                    writefln("        serverAuth        : %s", ext.get.serverAuth);
                    writefln("        clientAuth        : %s", ext.get.clientAuth);
                    writefln("        codeSigning       : %s", ext.get.codeSigning);
                    writefln("        emailProtection   : %s", ext.get.emailProtection);
                    writefln("        timeStamping      : %s", ext.get.timeStamping);
                    writefln("        ocspSigning       : %s", ext.get.ocspSigning);
                }
                else
                {
                    writefln("        <TODO: add a dedicated printer for this extension>");
                    writefln("        <For now take this autogenerated output>");
                    writefln("        %s", ext.get);
                }
            }

            return Result.noError;
        },
    ).resultEnforce;

    return 0;
}

private string toHexString(scope const(ubyte)[] bytes)
{
    import std.array     : Appender;
    import std.conv      : to;
    import std.exception : assumeUnique;

    Appender!(char[]) builder;

    foreach(i, byte_; bytes)
    {
        if(i != 0)
            builder.put(':');

        const hex = byte_.to!string(16);
        if(hex.length == 1)
            builder.put('0');
        builder.put(hex);
    }

    return builder.data.assumeUnique;
}

private string toString(Name name, string prefix)
{
    import std.array     : Appender;
    import std.exception : assumeUnique;
    import std.format    : format;

    import juptune.core.util : Result, resultEnforce;
    import juptune.data.x509 : X509Certificate, x509ForeachNameComponentGC, x509HandleNameComponent;

    Appender!(char[]) builder;

    uint i;
    x509ForeachNameComponentGC(
        name,
        handler: (component) {
            if(i++ != 0)
                builder.put('\n');

            X509Certificate.NameComponentKind kind;
            const(char)[] text;
            x509HandleNameComponent(component, kind, text).resultEnforce;

            builder.put(prefix);
            builder.put(format("%-22s", kind));
            builder.put(": ");
            builder.put(text);

            return Result.noError;
        }
    ).resultEnforce;

    return builder.data.assumeUnique;
}