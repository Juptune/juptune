/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.x509.validation;

import juptune.core.util : Result;
import juptune.data.x509.asn1convert : X509Certificate, X509Extension;
import juptune.data.x509.store : X509ExtensionStore;
import juptune.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Name;

enum X509ValidationError
{
    none,

    unknownSignatureAlgorithm,
    unknownKeyAlgorithm,
    keyAndSignatureAlgorithmMismatch,

    signatureCouldNotBeValidated,
    certificateHasExpired,
    certificateNotValidYet,
    namesDontMatch,
    certificateIsNotCa,
    certificateCannotSignCerts,
    certificateIsInvalid,
    tooManyCertificates,
}

struct X509CertificateValidationInfo
{
    X509Certificate* certificate;
    X509ExtensionStore* extensions;
}

Result x509ValidatePath(
    scope X509CertificateValidationInfo[] certPath,
    scope X509CertificateValidationInfo trustAnchor,
    X509Certificate.Time pointInTimeUtc,
) @nogc nothrow
{
    import juptune.core.ds : String;

    // Vars defined by the RFC 5280 6.1 algorithm
    auto workingPublicKeyAlgorithm = trustAnchor.certificate.subjectPublicKeyAlgorithm;
    auto workingPublicKey = trustAnchor.certificate.subjectPublicKey;
    auto workingIssuerName = trustAnchor.certificate.issuer;
    auto maxPathLength = certPath.length;

    // Custom vars
    auto workingCertInfo = trustAnchor;

    foreach(i, certInfo; certPath)
    {
        auto cert = certInfo.certificate;
        auto extStore = certInfo.extensions;
        assert(cert !is null, "user bug: certificate in certPath was null");
        assert(extStore !is null, "user bug: extensions store for certificate in certPath was null");

        // RFC 5280 6.1.4.k - Intentionally moved to the start since we operate on `i-1` here instead of `i`.
        //                    This was done so that some checks could also be performed on the trust anchor.
        const workingKeyUsage = workingCertInfo.extensions.getOrNull!(X509Extension.KeyUsage);
        const workingBasicConstraints = workingCertInfo.extensions.getOrNull!(X509Extension.BasicConstraints);
        if(!workingBasicConstraints.isNull)
        {
            if(!workingBasicConstraints.get.ca)
            {
                return Result.make(
                    X509ValidationError.certificateIsNotCa,
                    "Parent certificate is not a CA certificate - it cannot be used for verifying signatures",
                    String("Child certificate was certPath[", i, "]")
                );
            }

            if(!workingKeyUsage.isNull && !workingKeyUsage.get.keyCertSign)
            {
                return Result.make(
                    X509ValidationError.certificateCannotSignCerts,
                    "Parent certificate does not have the keyCertSign usage bit set - it cannot sign certificates let alone be used for verification", // @suppress(dscanner.style.long_line)
                    String("Child certificate was certPath[", i, "]")
                );
            }

            if(!workingBasicConstraints.get.pathLenConstraint.isNull && workingKeyUsage.isNull)
            {
                return Result.make(
                    X509ValidationError.certificateIsInvalid,
                    "Parent certificate has a pathLenConstraint set but does not have a keyUsage extension - this is not a valid certificate", // @suppress(dscanner.style.long_line)
                    String("Child certificate was certPath[", i, "]")
                );
            }
        }
        else if(workingCertInfo.certificate.version_ == X509Certificate.Version.v3)
        {
            // If the basic constraints extension is not present in a version 3 certificate [...] then the certified public key MUST NOT be used to verify certificate signatures
            return Result.make(
                X509ValidationError.certificateIsNotCa,
                "Parent certificate is not a CA certificate - it cannot be used for verifying signatures",
                String("Child certificate was certPath[", i, "]")
            );
        }

        // RFC 5280 6.1.4.m - Intentionally Moved
        if(
            !workingBasicConstraints.isNull 
            && !workingBasicConstraints.get.pathLenConstraint.isNull
            && workingBasicConstraints.get.pathLenConstraint.get < maxPathLength
        )
        {
            maxPathLength = workingBasicConstraints.get.pathLenConstraint.get;
        }

        // RFC 5280 6.1.4.n - Intentionally Moved
        if(!workingKeyUsage.isNull && !workingKeyUsage.get.keyCertSign)
        {
            return Result.make(
                X509ValidationError.certificateCannotSignCerts,
                "Parent certificate does not have the keyCertSign usage bit set - it cannot sign certificates let alone be used for verification", // @suppress(dscanner.style.long_line)
                String("Child certificate was certPath[", i, "]")
            );
        }

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
            return result.wrapError("when verifying signature:");
        if(!couldVerify)
        {
            return Result.make(
                X509ValidationError.signatureCouldNotBeValidated, 
                "Certificate's signature could not be validated using parent's public key",
                String("Certificate was certPath[", i, "]")
            );
        }

        // RFC 5280 6.1.3.a.2 - TODO: Lookup how to handle when pointInTimeUtc is == to either date?
        if(pointInTimeUtc.isAfter(cert.notValidAfter))
        {
            return Result.make(
                X509ValidationError.certificateHasExpired,
                "Certificate has expired",
                String(
                    "Certificate was certPath[", i, "] with notValidAfter of ", cert.notValidAfter,
                    " and pointOfTimeUtc of ", pointInTimeUtc
                )
            );
        }
        if(pointInTimeUtc.isBefore(cert.notValidBefore))
        {
            return Result.make(
                X509ValidationError.certificateNotValidYet,
                "Certificate is not yet valid",
                String(
                    "Certificate was certPath[", i, "] with notValidBefore of ", cert.notValidBefore,
                    " and pointOfTimeUtc of ", pointInTimeUtc
                )
            );
        }

        // RFC 5280 6.1.3.a.3
        // TODO: Support CRLs

        // RFC 5280 6.1.3.a.4
        result = x509AreNamesEqual(workingIssuerName, cert.issuer);
        if(result.isError)
            return result.wrapError("when comparing issuer names:"); // TODO: Probably helpful to add the cert index to the String context.

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

        // RFC 5280 6.1.4.j
        // TODO: Support inhibitAnyPolicy

        // RFC 5280 6.1.4.l
        bool isSelfSigned = false; // TODO: Figure out how to detect
        if(!isSelfSigned)
        {
            if(maxPathLength == 0)
            {
                return Result.make(
                    X509ValidationError.tooManyCertificates,
                    "Too many certificates were checked, likely due to the trust anchor/an intermidary certificate setting a pathLenConstraint", // @suppress(dscanner.style.long_line)
                    String("Certificate was certPath[", i, "]")
                );
            }
            maxPathLength--;
        }

        // RFC 5280 6.1.4.o
        // TODO: Support Policy Constraints

        // Custom
        workingCertInfo = certInfo;
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
    import std.digest.sha : sha1Of, sha224Of, sha256Of, sha384Of, sha512Of;
    import std.sumtype : match;

    import juptune.core.ds : String;
    import juptune.crypto.rsa : RsaPublicKey, RsaPadding, RsaSignatureAlgorithm;
    import juptune.crypto.ecdsa : EcdsaPublicKey, EcdsaGroupName, EcdsaSignatureAlgorithm;
    import juptune.asn1.decode.bcd.encoding : asn1DecodeComponentHeader, Asn1ComponentHeader, Asn1Ruleset;
    import juptune.data.buffer : MemoryReader;
    import juptune.data.x509.asn1convert : X509SignatureAlgorithm, X509PublicKeyAlgorithm;
    
    import juptune.asn1.generated.raw.PKIX1Algorithms88_1_3_6_1_5_5_7_0_17
        :
            EcpkParameters
        ;
    
    Result handleRsa()
    {
        // Decode the trust anchor's public key
        RsaPublicKey publicKey;
        auto result = RsaPublicKey.fromAsn1RsaPublicKeyBytes(trustAnchorKey.bytes, publicKey);
        if(result.isError)
            return result.wrapError("when decoding RSA trust anchor public key:");

        // Perform hash + set hash parameters
        union Hash
        {
            ubyte[20] sha1;
            ubyte[28] sha224;
            ubyte[32] sha256;
            ubyte[48] sha384;
            ubyte[64] sha512;
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
            (X509SignatureAlgorithm.Sha244WithRsaEncryption _){
                sigAlgorithm = RsaSignatureAlgorithm.sha224;
                hashBuffer.sha224 = sha224Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha224[];
                return Result.noError;
            },
            (X509SignatureAlgorithm.Sha256WithRsaEncryption _){
                sigAlgorithm = RsaSignatureAlgorithm.sha256;
                hashBuffer.sha256 = sha256Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha256[];
                return Result.noError;
            },
            (X509SignatureAlgorithm.Sha384WithRsaEncryption _){
                sigAlgorithm = RsaSignatureAlgorithm.sha384;
                hashBuffer.sha384 = sha384Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha384[];
                return Result.noError;
            },
            (X509SignatureAlgorithm.Sha512WithRsaEncryption _){
                sigAlgorithm = RsaSignatureAlgorithm.sha512;
                hashBuffer.sha512 = sha512Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha512[];
                return Result.noError;
            },
            (_) => Result.make(
                X509ValidationError.keyAndSignatureAlgorithmMismatch,
                "Trust anchor key is RSA while subject's signature algorithm does not use RSA",
                String("subject signature algorithm was of type: ", typeof(_).stringof)
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

    Result handleEcdsa(EcpkParameters params)
    {
        import juptune.data.x509.asn1convert : x509HandleNamedCurveIdentifierRfc5480;

        if(!params.isNamedCurve)
            return Result.make(X509ValidationError.certificateIsInvalid, "for ECDSA trust anchor public key, EcpkParamaters may only be the namedCurve option - all other options are forbidden for PKIX purposes under RFC 5480"); // @suppress(dscanner.style.long_line)

        EcdsaGroupName namedCurve;
        auto result = x509HandleNamedCurveIdentifierRfc5480(params.getNamedCurve(), namedCurve);
        if(result.isError)
            return result.wrapError("when handling ECDSA trust anchor public key:");

        // Decode the trust anchor's public key
        EcdsaPublicKey publicKey;
        result = EcdsaPublicKey.fromBytes(
            namedCurve,
            trustAnchorKey.bytes, 
            publicKey
        );
        if(result.isError)
            return result.wrapError("when decoding ECDSA trust anchor public key:");

        // Perform hash + set hash parameters
        union Hash
        {
            ubyte[20] sha1;
            ubyte[28] sha224;
            ubyte[32] sha256;
            ubyte[48] sha384;
            ubyte[64] sha512;
        }

        Hash hashBuffer;
        const(ubyte)[] subjectHash;
        EcdsaSignatureAlgorithm sigAlgorithm;
        
        result = subjectSignatureAlgorithm.match!(
            (X509SignatureAlgorithm.EcdsaWithSha1 _){
                return Result.make(X509ValidationError.unknownSignatureAlgorithm, "EcdsaWithSha1 is not supported");
            },
            (X509SignatureAlgorithm.EcdsaWith244 _){
                return Result.make(X509ValidationError.unknownSignatureAlgorithm, "EcdsaWith244 is not supported");
            },
            (X509SignatureAlgorithm.EcdsaWith256 _){
                sigAlgorithm = EcdsaSignatureAlgorithm.sha256;
                hashBuffer.sha256 = sha256Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha256[];
                return Result.noError;
            },
            (X509SignatureAlgorithm.EcdsaWith384 _){
                sigAlgorithm = EcdsaSignatureAlgorithm.sha384;
                hashBuffer.sha384 = sha384Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha384[];
                return Result.noError;
            },
            (X509SignatureAlgorithm.EcdsaWith512 _){
                sigAlgorithm = EcdsaSignatureAlgorithm.sha512;
                hashBuffer.sha512 = sha512Of(subjectTbsRawDer);
                subjectHash = hashBuffer.sha512[];
                return Result.noError;
            },
            (_) => Result.make(
                X509ValidationError.keyAndSignatureAlgorithmMismatch,
                "Trust anchor key is ECDSA while subject's signature algorithm does not use ECDSA",
                String("subject signature algorithm was of type: ", typeof(_).stringof)
            ),
        );
        if(result.isError)
            return result;

        return publicKey.verifySignature(
            subjectSignature.bytes, 
            subjectHash, 
            sigAlgorithm, 
            couldVerify
        );
    }

    auto result = trustAnchorKeyAlgorithm.match!(
        (X509PublicKeyAlgorithm.RsaEncryption _) => handleRsa(),
        (X509PublicKeyAlgorithm.EcPublicKey ecdsa) => handleEcdsa(ecdsa.params),
        (X509PublicKeyAlgorithm.Unknown unknown) {
            return Result.make(
                X509ValidationError.unknownKeyAlgorithm,
                "Trust anchor contains an unknown/unsupported key algorithm for its subjectPublicKey",
                String("algorithm OID was: TODO")
            );
        },
        (_) { assert(false, "Unimplemented verification for "~typeof(_).stringof); return Result.noError; }
    );
    if(result.isError)
        return result;

    return Result.noError;
}

Result x509AreNamesEqual(Name a, Name b) @nogc nothrow
{
    import juptune.core.ds : Array, String;
    import juptune.data.buffer : MemoryReader;
    import juptune.asn1.decode.bcd.encoding : Asn1Ruleset, Asn1Identifier, Asn1Ia5String, Asn1PrintableString;
    import juptune.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : AttributeTypeAndValue;

    Result toArray(Name name, out Array!AttributeTypeAndValue array)
    {
        return name.getRdnSequence().get().foreachElementAuto((rdn){
            return rdn.get().foreachElementAuto((typeAndValue){
                array.put(typeAndValue);
                return Result.noError;
            });
        });
    }

    Array!AttributeTypeAndValue aNames;
    Array!AttributeTypeAndValue bNames;
    if(auto r = toArray(a, aNames)) return r;
    if(auto r = toArray(b, bNames)) return r;

    if(aNames.length != bNames.length)
    {
        return Result.make(
            X509ValidationError.namesDontMatch,
            "names do not match: names contain a different amount of components",
            String("name A contains ", aNames.length, " components; name B contains ", bNames.length, " components")
        );
    }

    foreach(i, aComp; aNames[])
    {
        auto bComp = bNames[i];

        if(aComp.getType() != bComp.getType())
        {
            import std.algorithm : map;
            return Result.make(
                X509ValidationError.namesDontMatch,
                "names do not match: component types do not match",
                String(
                    "component #", i, 
                    " for name A is of type ", aComp.getType().get().components.map!(b => b.isNull ? -1 : b.get),
                    "; for name B is of type ", bComp.getType().get().components.map!(b => b.isNull ? -1 : b.get)
                )
            );
        }

        if(aComp.getValue().identifier != bComp.getValue().identifier)
        {
            return Result.make(
                X509ValidationError.namesDontMatch,
                "names cannot be compared: component values are different ASN.1 types (this is actually a Juptune limitation TODO: fix)", // @suppress(dscanner.style.long_line)
                String(
                    "component #", i, 
                    " for name A is of value type ", aComp.getValue().identifier,
                    "; for name B is of value type ", bComp.getValue().identifier
                )
            );
        }

        // Technically some of the options break the primitive assumption, but for now they're unsupported, so having this catch-all is useful.
        const id = aComp.getValue().identifier;
        if(id.class_ != Asn1Identifier.Class.universal || id.encoding != Asn1Identifier.Encoding.primitive)
        {
            return Result.make(
                X509ValidationError.namesDontMatch,
                "names cannot be compared: expected component to be of a UNIVERSAL tag and primitively constructed",
                String("component #", i, " for both names have an identifier of ", id)
            );
        }

        auto aMem = MemoryReader(aComp.getValue().value.data);
        auto bMem = MemoryReader(bComp.getValue().value.data);

        Result getAs(T)(out T a, out T b)
        {
            if(auto r = T.fromDecoding!(Asn1Ruleset.der)(aMem, a, id)) return r;
            return T.fromDecoding!(Asn1Ruleset.der)(bMem, b, id);
        }

        Result simpleCompare(T)()
        {
            T aStr, bStr;
            if(auto r = getAs(aStr, bStr)) return r;
            if(aStr.asSlice != bStr.asSlice)
            {
                return Result.make(
                    X509ValidationError.namesDontMatch,
                    "names do not match: components are not equal",
                    String("component #", i, " for name A is `", aStr.asSlice, "`; for name B is `", bStr.asSlice, "`") // @suppress(dscanner.style.long_line)
                );
            }
            return Result.noError;
        }

        // TODO: Implement RFC 5280 7.1 properly (remember to include RFC 9549)
        switch(id.tag)
        {
            // TODO: I should really find a central place to store ASN.1's UNIVERSAL tags
            case 22: // IA5String
                if(auto r = simpleCompare!Asn1Ia5String()) return r;
                break;

            case 19: // PrintableString
                if(auto r = simpleCompare!Asn1PrintableString()) return r;
                break;

            default: return Result.make(
                X509ValidationError.namesDontMatch,
                "names cannot be compared: components are of an unknown/unsupported type",
                String("component #", i, " for both names have an identifier of ", id)
            );
        }
    }

    return Result.noError;
}

Result x509IsSelfSigned(scope X509CertificateValidationInfo info, scope out bool isSelfSigned) @nogc nothrow
in(info.certificate !is null)
in(info.extensions !is null)
{
    // Check 1: See if the key identifiers match.
    auto subjectKey = info.extensions.getOrNull!(X509Extension.SubjectKeyIdentifier);
    auto authorityKey = info.extensions.getOrNull!(X509Extension.AuthorityKeyIdentifier);
    if(!subjectKey.isNull && !authorityKey.isNull && subjectKey.get.keyIdentifier == authorityKey.get.keyIdentifier)
    {
        isSelfSigned = true;
        return Result.noError;
    }

    // Check 2: See if the issuer and subject match.
    auto result = x509AreNamesEqual(info.certificate.issuer, info.certificate.subject);
    if(result.isError && !result.isError(X509ValidationError.namesDontMatch))
        return result;
    else if(!result.isError)
    {
        isSelfSigned = true;
        return Result.noError;
    }

    return Result.noError;
}

@("validation.d - General megatest")
unittest
{
    import std.file : fileRead = read, exists;
    import juptune.core.util : resultAssert;
    import juptune.asn1.decode.bcd.encoding 
        : Asn1DecodeError, Asn1ComponentHeader, Asn1Ruleset, asn1ReadContentBytes, asn1DecodeComponentHeader;
    import juptune.data.buffer : MemoryReader;
    import juptune.data.x509 : X509Certificate, x509FromAsn1;
    import juptune.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Certificate;

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

    x509ValidatePath(
        [X509CertificateValidationInfo(&signedRsa, &signedRsaExt)],
        X509CertificateValidationInfo(&selfSigned, &selfSignedExt),
        X509Certificate.Time(2004, 10, 1, 1, 1, 1)
    ).resultAssert;
}