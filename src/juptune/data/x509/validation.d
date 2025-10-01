/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.x509.validation;

import juptune.core.util : Result;
import juptune.data.x509.asn1convert : X509Certificate;
import juptune.data.x509.store : X509ExtensionStore;
import juptune.data.asn1.generated.raw.CryptographicMessageSyntaxAlgorithms_1_2_840_113549_1_9_16_0_16;

enum X509ValidationError
{
    none,

    unknownSignatureAlgorithm,
    unknownKeyAlgorithm,
    keyAndSignatureAlgorithmMismatch,

    signatureCouldNotBeValidated,
    certificateHasExpired,
    certificateNotValidYet,
    issuerMismatch,
}

struct X509CertificateValidationInfo
{
    X509Certificate* certificate;
    X509ExtensionStore* extensions;
}

Result x509ValidatePath(
    scope X509CertificateValidationInfo[] certPath,
    scope ref X509CertificateValidationInfo trustAnchor,
    X509Certificate.Time pointInTimeUtc,
) @nogc nothrow
{
    import juptune.core.ds : String2;

    auto workingPublicKeyAlgorithm = trustAnchor.certificate.subjectPublicKeyAlgorithm;
    auto workingPublicKey = trustAnchor.certificate.subjectPublicKey;
    auto workingIssuerName = trustAnchor.certificate.issuer;
    auto maxPathLength = certPath.length;

    foreach(i, certInfo; certPath)
    {
        auto cert = certInfo.certificate;
        auto extStore = certInfo.extensions;
        assert(cert !is null, "user bug: certificate in certPath was null");
        assert(extStore !is null, "user bug: extensions store for certificate in certPath was null");

        // RFC 5280 6.1.3.a.1
        bool couldVerify;
        auto result = x509VerifySignature(
            workingPublicKeyAlgorithm,
            workingPublicKey,
            cert.signatureAlgorithm,
            cert.signatureValue,
            cert.tbsCertificateRawDerEncoding,
            couldVerify,
        );
        if(result.isError)
            return result;
        if(!couldVerify)
        {
            return Result.make(
                X509ValidationError.signatureCouldNotBeValidated, 
                "Certificate's signature could not be validated using parent's public key",
                String2("Certificate was certPath[", i, "]")
            );
        }

        // RFC 5280 6.1.3.a.2 - TODO: Lookup how to handle when pointInTimeUtc is == to either date?
        if(cert.notValidAfter.isBefore(pointInTimeUtc))
        {
            return Result.make(
                X509ValidationError.certificateHasExpired,
                "Certificate has expired",
                String2("Certificate was certPath[", i, "] with notValidAfter of ", cert.notValidAfter)
            );
        }
        if(cert.notValidBefore.isAfter(pointInTimeUtc))
        {
            return Result.make(
                X509ValidationError.certificateNotValidYet,
                "Certificate is not yet valid",
                String2("Certificate was certPath[", i, "] with notValidBefore of ", cert.notValidBefore)
            );
        }

        // RFC 5280 6.1.3.a.3
        // TODO: Support CRLs

        // RFC 5280 6.1.3.a.4
        // WARY: This is highly dependent on Dasn1's output not somehow generating unique fields for otherwise identical inputs.
        // NOTE: Because of DER and the fact that names are hierarchical, a byte-wise comparison should be correct?
        const trustIssuer = cast(ubyte[])(&workingIssuerName)[0..1];
        const subjectIssuer = cast(ubyte[])(&cert.issuer)[0..1];
        if(trustIssuer != subjectIssuer)
        {
            return Result.make(
                X509ValidationError.issuerMismatch,
                "Certificate's issuer is not the same as its parent's issuer",
                String2(
                    "Certificate was certPath[", i, "] with issuer of (TODO format) ", subjectIssuer, 
                    " and parent issuer of (TODO format) ", trustIssuer,
                )
            );
        }

        // RFC 5280 6.1.3.b
        // TODO: Support Permitted Subtrees

        // RFC 5280 6.1.3.c
        // TODO: Support Excluded Subtrees

        // RFC 5280 6.1.3.d
        // TODO: Support Certificate Policies

        // RFC 5280 6.1.3.e
        // TODO: Support Certificate Policies

        // RFC 5280 6.1.3.f
        // TODO: Support Policies

        if(i == certPath.length - 1) // @suppress(dscanner.suspicious.length_subtraction)
            break; // Head into the wrap up stage.

        // RFC 5280 6.1.4.a
        // TODO: Support Policy Mappings

        // RFC 5280 6.1.4.b
        // TODO: Support Policy Mappings

        // RFC 5280 6.1.4.c
        workingIssuerName = cert.subject;

        // RFC 5280 6.1.4.d
        workingPublicKey = cert.subjectPublicKey;

        // RFC 5280 6.1.4.e
        // TODO: Need to look into that parameter propagation stuff... it might be annoying

        // RFC 5280 6.1.4.f
        workingPublicKeyAlgorithm = cert.subjectPublicKeyAlgorithm;

        // RFC 5280 6.1.4.g
        // TODO: Support Name Constraints

        // RFC 5280 6.1.4.h
        // TODO: Figure out how to detect self-issued certificates, since there's apparently multiple ways, each of which is non-decisive (lol)

        // RFC 5280 6.1.4.i
        // TODO: Support Policy Constraints
    }

    auto finalCert = certPath[$-1].certificate;
    auto finalExtStore = certPath[$-1].extensions;

    // RFC 5280 6.1.5.a
    // TODO: Support explict_policy

    // RFC 5280 6.1.5.b
    // TODO: Support Policy Constraints

    // RFC 5280 6.1.5.c
    workingPublicKey = finalCert.subjectPublicKey;

    // RFC 5280 6.1.5.d
    // TODO: Need to look into that parameter propagation stuff... it might be annoying

    // RFC 5280 6.1.5.e
    workingPublicKeyAlgorithm = finalCert.subjectPublicKeyAlgorithm;

    // RFC 5280 6.1.5.f
    // TODO: Handle any remaining supported extensions

    // RFC 5280 6.1.5.f
    // TODO: Support valid_policy_tree and user-initial-policy-set

    return Result.noError;
}

Result x509VerifySignature(
    // NOTE: I'm intentionally using typeof to document which fields to get the parameters from.
    scope typeof(X509Certificate.subjectPublicKeyAlgorithm) trustAnchorKeyAlgorithm,
    scope typeof(X509Certificate.subjectPublicKey) trustAnchorKey,
    scope typeof(X509Certificate.signatureAlgorithm) subjectSignatureAlgorithm,
    scope typeof(X509Certificate.signatureValue) subjectSignature,
    scope typeof(X509Certificate.tbsCertificateRawDerEncoding) subjectTbsRawDer,
    scope out bool couldVerify,
) @nogc nothrow
{
    import std.digest.sha : sha1Of;
    import std.sumtype : match;

    import juptune.core.ds : String2;
    import juptune.crypto.rsa : RsaPublicKey, RsaPadding, RsaSignatureAlgorithm;
    import juptune.data.asn1.decode.bcd.encoding : asn1DecodeComponentHeader, Asn1ComponentHeader, Asn1Ruleset;
    import juptune.data.buffer : MemoryReader;
    import juptune.data.x509.asn1convert : X509SignatureAlgorithm, X509PublicKeyAlgorithm;

    import juptune.data.asn1.generated.raw.PKIX1Algorithms88_1_3_6_1_5_5_7_0_17
        :
            RSAPublicKey
        ;

    auto anchorKeyMem = MemoryReader(trustAnchorKey.bytes);

    Asn1ComponentHeader anchorKeyHeader;
    auto result = asn1DecodeComponentHeader!(Asn1Ruleset.der)(anchorKeyMem, anchorKeyHeader);
    if(result.isError)
        return result;

    Result handleRsa()
    {
        // Decode the trust anchor's public key
        RSAPublicKey asn1PublicKey;
        auto result = asn1PublicKey.fromDecoding!(Asn1Ruleset.der)(anchorKeyMem, anchorKeyHeader.identifier);
        if(result.isError)
            return result;

        RsaPublicKey publicKey;
        result = RsaPublicKey.fromBigEndianBytes(
            asn1PublicKey.getModulus().rawBytes,
            asn1PublicKey.getPublicExponent().rawBytes,
            publicKey
        );
        if(result.isError)
            return result;

        // Perform hash + set hash parameters
        union Hash
        {
            ubyte[20] sha1;
        }

        Hash hashBuffer;
        const(ubyte)[] subjectHash;
        RsaSignatureAlgorithm sigAlgorithm;
        
        result = subjectSignatureAlgorithm.match!(
            (X509SignatureAlgorithm.Sha1WithRsaEncryption _){
                sigAlgorithm = RsaSignatureAlgorithm.sha1;
                hashBuffer.sha1 = sha1Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha1[];
                return Result.noError;
            },
            (_) => Result.make(
                X509ValidationError.keyAndSignatureAlgorithmMismatch,
                "Trust anchor key is RSA while subject's signature algorithm does not use RSA",
                String2("subject signature algorithm was of type: ", typeof(_).stringof)
            ),
        );
        if(result.isError)
            return result;

        return publicKey.verifySignature(
            subjectSignature.bytes, 
            subjectHash, 
            RsaPadding.pkcs1, 
            sigAlgorithm, 
            couldVerify
        );
    }

    result = trustAnchorKeyAlgorithm.match!(
        (X509PublicKeyAlgorithm.RsaEncryption _) => handleRsa(),
        (X509PublicKeyAlgorithm.Unknown unknown) {
            return Result.make(
                X509ValidationError.unknownKeyAlgorithm,
                "Trust anchor contains an unknown/unsupported key algorithm for its subjectPublicKey",
                String2("algorithm OID was: TODO")
            );
        },
        (_) { assert(false, "Unimplemented verification for "~typeof(_).stringof); return Result.noError; }
    );
    if(result.isError)
        return result;

    return Result.noError;
}

@("TEMP")
unittest
{
    import std.file : fileRead = read, exists;
    import juptune.core.util : resultAssert;
    import juptune.data.asn1.decode.bcd.encoding 
        : Asn1DecodeError, Asn1ComponentHeader, Asn1Ruleset, asn1ReadContentBytes, asn1DecodeComponentHeader;
    import juptune.data.buffer : MemoryReader;
    import juptune.data.x509 : X509Certificate, x509FromAsn1;
    import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Certificate;

    X509Certificate readCert(string path)
    {
        if(!path.exists) // Check if we're running from the build dir instead of the root dir (e.g. because of `meson test`).
            path = "../"~path;

        auto memory = MemoryReader(cast(ubyte[])fileRead(path));
        
        Asn1ComponentHeader header;
        MemoryReader content;
        asn1DecodeComponentHeader!(Asn1Ruleset.der)(memory, header).resultAssert;
        asn1ReadContentBytes(memory, header.length, content).resultAssert;

        Certificate asn1Cert;
        asn1Cert.fromDecoding!(Asn1Ruleset.der)(content, header.identifier).resultAssert;

        X509Certificate cert;
        x509FromAsn1(asn1Cert, cert).resultAssert;

        return cert;
    }

    if(!exists("./data/test/asn1") && !exists("../data/test/asn1"))
    {
        import std.stdio : writeln;
        writeln("[SKIP] Cannot find ./data or ../data - juptune-unittest is being ran somewhere weird, skipping test.");
        return;
    }
    
    auto selfSigned = readCert("data/test/asn1/rfc5280-ref-certs/self-signed.cer");
    auto signedRsa = readCert("data/test/asn1/rfc5280-ref-certs/signed-rsa.cer");

    bool couldVerify;
    x509VerifySignature(
        selfSigned.subjectPublicKeyAlgorithm,
        selfSigned.subjectPublicKey,
        selfSigned.signatureAlgorithm,
        selfSigned.signatureValue,
        selfSigned.tbsCertificateRawDerEncoding,
        couldVerify
    ).resultAssert;
    assert(couldVerify);

    x509VerifySignature(
        selfSigned.subjectPublicKeyAlgorithm,
        selfSigned.subjectPublicKey,
        signedRsa.signatureAlgorithm,
        signedRsa.signatureValue,
        signedRsa.tbsCertificateRawDerEncoding,
        couldVerify
    ).resultAssert;
    assert(couldVerify);

    X509ExtensionStore selfSignedExt, signedRsaExt;
    X509ExtensionStore.fromCertificate(selfSigned, selfSignedExt).resultAssert;
    X509ExtensionStore.fromCertificate(signedRsa, signedRsaExt).resultAssert;
}