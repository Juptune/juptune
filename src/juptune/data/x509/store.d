/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.x509.store;

import juptune.core.util : Result;
import juptune.data.x509.asn1convert : X509Certificate, X509Extension;

/// A `Result` error enum
enum X509StoreError
{
    none,
    
    extensionAlreadySet,    /// An Extension of a certain type has already been set within an `X509ExtensionStore`

    duplicateSubjectKeyId,  /// A certificate with the given subjectKeyIdentifier has already been loaded into an `X509CertificateStore`
    trustAnchorNotFound,    /// A certificate's trust anchor could not be found during validation within an `X509CertificateStore`
}

/++
 + A type for easily storing and accessing the various different extensions that have built-in support.
 +
 + Notes:
 +  This type isn't super great for unknown extensions (i.e. extensions that the user code may recognise).
 + ++/
struct X509ExtensionStore
{
    import std.traits : TemplateArgsOf, staticMap;
    import std.typecons : Nullable;

    import juptune.core.ds : HashMap, Array;

    private
    {
        alias Types = TemplateArgsOf!(X509Extension.SumT)[1..$];
        alias NullableTypes = staticMap!(Nullable, Types);
        
        NullableTypes _extensions;
        Array!(X509Extension.Unknown) _unknowns;

        static size_t indexOf(T)() @nogc nothrow pure
        {
            static foreach(i, Type; Types)
            {
                static if(is(Type == T))
                {
                    enum Found = true; // @suppress(dscanner.suspicious.unused_variable)
                    return i;
                }
            }

            static if(!__traits(compiles, { bool b = Found; }))
                static assert(false, "Type "~T.stringof~" is not a valid extension type");
        }
    }

    @disable this(this);

    /++
     + Loads all of the extensions of the given certificate into the provided store.
     +
     + Notes:
     +  This function is destructive - `store`'s original contents will be overwritten.
     +
     +  This function currently only allocates memory to store a list of unknown extensions.
     +
     +  This function does not perform a deep copy. The original underlying bytes for the `X509Certificate` MUST
     +  be kept allocated an unmodified for its entire lifetime, and that extends to its extensions.
     +
     +  `cert` is passed by ref for efficiency since it's very large.
     +
     + Params:
     +  cert  = The certificate to extract the extensions from.
     +  store = The store to initialise.
     +
     + Throws:
     +  Anything that `Asn1SequenceOf.foreachElementAuto` can throw.
     +
     +  Anything that `x509HandleExtension` can throw.
     +
     +  Anything that `X509ExtensionStore.set` can throw.
     +
     + Returns:
     +  A `Result` indicating if an error occurred or not.
     + ++/
    static Result fromCertificate(ref X509Certificate cert, scope ref typeof(this) store) @nogc nothrow
    {
        import juptune.data.x509.asn1convert : x509HandleExtension;

        store = typeof(this).init;
        if(cert.extensions.isNull)
            return Result.noError;

        return cert.extensions.get.get().foreachElementAuto((element){
            X509Extension.SumT ext;
            auto result = x509HandleExtension(element, ext);
            if(result.isError)
                return result;

            import std.sumtype : match;
            return ext.match!(
                (X509Extension.Unknown unknown) { store.putUnknown(unknown); return Result.noError; },
                (e) { return store.set(e); }
            );
        });
    }

    /++
     + Stores an unknown extension.
     +
     + Notes:
     +  Currently no attempt is made to ensure the extension's OID is unique.
     + ++/
    void putUnknown(X509Extension.Unknown unknown) @nogc nothrow
    {
        this._unknowns.put(unknown);
    }

    /++ 
     + Sets the value of an extension.
     +
     + Params:
     +  extension = The extension to set.
     +
     + Throws:
     +  `X509StoreError.extensionAlreadySet` if an extension of type `T` has already been set.
     +
     + Returns:
     +  A `Result` indicating if an error occurred or not.
     + ++/
    Result set(T)(T extension)
    {
        scope ptr = &this._extensions[indexOf!T];
        if(!ptr.isNull)
        {
            return Result.make(
                X509StoreError.extensionAlreadySet,
                "Extension of type "~T.stringof~" has already been set within this store"
            );
        }
        *ptr = extension;
        return Result.noError;
    }
    
    ///
    ref const(Array!(X509Extension.Unknown)) getUnknownExtensions() @nogc nothrow const => this._unknowns;
    
    /++
     + Gets the value of an extension if it was set, or null.
     +
     + Params:
     +  `T` = The type of the extension to get the value of.
     +
     + Returns:
     +  An instance of the extension of type `T`, or a null `Nullable` if the extension wasn't found.
     + ++/
    Nullable!T getOrNull(T)() => this._extensions[indexOf!T];
}

/++
 + Stores certificates and acts as the main high-level entrypoint for dealing with x.509 certificates.
 +
 + This type provides a ton of helper functions to make dealing with loading and validation of certificates easier.
 +
 + Trust anchor selection:
 +  When a certificate or certificate chain is verified there must be a "trust anchor" (i.e. a root certificate) that
 +  can be used to verify the certificate/chain's signature.
 +
 +  The following options are attempted by this type for identifying the trust anchor of a certificate (or for chains: the first certificate
 +  in the chain is used for identifying the anchor).
 +
 +  *authorityKeyIdentifier* - If the target certificate contains the authorityKeyIdentifier extension, then a lookup for a certficate
 +  that has a matching subjectKeyIdentifier extension is performed. If the identifiers match, then the looked up certificate 
 +  is used as the trust anchor.
 + ++/
struct X509CertificateStore
{
    import juptune.core.ds : Array, HashMap, String2;

    /// An aggregate type storing a bunch of information about an x.509 certificate.
    static struct Cert
    {
        X509Certificate certificate;
        X509ExtensionStore extensions;
        
        private Array!ubyte underlyingBytes;

        @disable this(this);
    }

    private
    {
        alias HashedKey = ubyte[16];

        Array!(Cert*) _certs; // Source of truth - hold all loaded certificates.
        HashMap!(HashedKey, Cert*) _certByHashedSubjectKey; // View of _certs - easy way to access cert by their subject key
    }

    ~this() @nogc nothrow
    {
        import core.stdc.stdlib : free;
        foreach(cert; this._certs.slice)
        {
            (*cert).__xdtor();
            free(cert);
        }
    }

    /++
     + Loads - and optionally validates - a certificate from the given raw DER encoding stored in `derBytes`.
     + The resulting certificate is then stored within this certificate store.
     +
     + Notes:
     +  This function copies the bytes within `derBytes` into its internal storage, alleviating the user code
     +  from having to preserve the lifetime of `derBytes`. In other words, as long as this instance of `X509CertificateStore`
     +  is alive, then all of the certificates this function parses will be alive.
     +
     +  To be clear, `derBytes` must contain the DER encoding of the ASN.1 x.509 `Certificate` structure.
     +
     +  Validation is only performed if `hasImplicitTrust` is `false`. If validation is performed, then trust
     +  anchor selection is performed. Please see the certiciate store's main documentation comment for details.
     +
     +  Set `hasImplicitTrust` to true for root certificates/trust anchors.
     +
     +  This function only loads a single certificate, for a certificate chain please see TODO
     +
     +  If an error is generated then no certificate is stored and any allocated memory for the certificate is immediately freed.
     +
     + Params:
     +  derBytes = The DER encoded `Certificate` to copy and decode.
     +  hasImplicitTrust = If true, then the certificate will not be validated. If false, then the certificate will be validated.
     +
     + Throws:
     +  Anything that the underlying ASN.1 decoder functions can throw (`Asn1DecodeError`).
     +
     +  Anything that `x509FromAsn1` can throw.
     +
     +  Anything that `X509ExtensionStore.fromCertificate` can throw.
     +
     +  Anything that `x509ValidatePath` can throw.
     +
     +  `X509StoreError.trustAnchorNotFound` if `hasImplicitTrust` is false and no trust anchor could be determined for the certificate.
     +
     +  `X509StoreError.duplicateSubjectKeyId` if the certificate contains the subjectKeyIdentifier extension, and the identifier
     +  has already been used by a previous certificate.
     +
     + Returns:
     +  A `Result` indicating if an error occurred or not.
     + ++/
    Result loadFromCopyingDerBytes(scope const(ubyte)[] derBytes, bool hasImplicitTrust = false) @nogc nothrow
    in(derBytes.length > 0, "derBytes is empty")
    {
        import core.stdc.stdlib : calloc, free;
        import core.exception : onOutOfMemoryErrorNoGC;

        import juptune.data.x509.validation : x509ValidatePath;

        auto certPtr = cast(Cert*)calloc(1, Cert.sizeof);
        if(certPtr is null)
            onOutOfMemoryErrorNoGC();
        certPtr.underlyingBytes.put(derBytes);

        auto result = this.loadCert(certPtr);
        if(result.isError)
            return result;

        if(hasImplicitTrust)
            return this.storeCert(certPtr);

        result = this.validateSingleCert(certPtr);
        if(result.isError)
        {
            (*certPtr).__xdtor();
            free(certPtr);
            return result;
        }

        return this.storeCert(certPtr);
    }

    /++
     + Looks up a certificate by its subjectKeyIdentifier, or null if no certificate was found.
     +
     + Notes:
     +  For your own good, please do not modify any of the data in returned pointer.
     +
     + Params:
     +  sujectKeyId = The subject key identifier to lookup.
     +
     + Returns:
     +  The identified `Cert*`, or `null` if no certificate could be identified.
     + ++/
    Cert* getBySubjectKeyIdOrNull(scope const(ubyte)[] subjectKeyId) @nogc nothrow
    in(subjectKeyId.length > 0, "subjectKeyId is empty")
    {
        const hash = this.hashKey(subjectKeyId);
        return this._certByHashedSubjectKey.get(hash, default_: null);
    }

    private X509Certificate.Time currTime() @nogc nothrow
    {
        import core.stdc.time : time, gmtime;
        
        auto epoch = time(null);
        auto utc = gmtime(&epoch);
        assert(utc !is null, "TODO: What do I even do here - it's a weird Result to return :laugh:");
        assert(utc.tm_gmtoff == 0, "Time isn't UTC?");

        return X509Certificate.Time(
            cast(ushort)(utc.tm_year + 1900),
            cast(ubyte)(utc.tm_mon + 1),
            cast(ubyte)utc.tm_mday,
            cast(ubyte)utc.tm_hour,
            cast(ubyte)utc.tm_min,
            cast(ubyte)utc.tm_sec,
        );
    }

    private Result validateSingleCert(Cert* cert) @nogc nothrow
    {
        import juptune.data.x509.validation : x509ValidatePath, X509CertificateValidationInfo;

        Cert* trustAnchor;
        auto result = this.findTrustAnchor(cert, trustAnchor);
        if(result.isError)
            return result;

        const pointInTimeUtc = this.currTime();
        return x509ValidatePath(
            [X509CertificateValidationInfo(&cert.certificate, &cert.extensions)], 
            X509CertificateValidationInfo(&trustAnchor.certificate, &trustAnchor.extensions),
            pointInTimeUtc
        );
    }

    private Result findTrustAnchor(Cert* forCert, out Cert* trustAnchor) @nogc nothrow
    {
        auto authKeyId = forCert.extensions.getOrNull!(X509Extension.AuthorityKeyIdentifier);
        if(!authKeyId.isNull)
        {
            trustAnchor = this.getBySubjectKeyIdOrNull(authKeyId.get.keyIdentifier);
            if(trustAnchor is null)
            {
                return Result.make(
                    X509StoreError.trustAnchorNotFound,
                    "certificate's authorityKeyIdentifier refers to a trust anchor that has not been loaded yet",
                    String2("authorityKeyIdentifier was: ", authKeyId.get.keyIdentifier)
                );
            }

            return Result.noError;
        }

        return Result.make(
            X509StoreError.trustAnchorNotFound,
            "unable to determine method for trust anchor lookup out of options: "
            ~"authorityKeyIdentifier"
        );
    }

    private HashedKey hashKey(scope const(ubyte)[] key) @nogc nothrow pure
    {
        import std.digest.murmurhash : MurmurHash3;
        MurmurHash3!(128, 64) hasher;
        hasher.put(key);
        return hasher.finish();
    }

    private Result storeCert(Cert* cert) @nogc nothrow
    {
        HashedKey subjectKeyHash;
        auto subjectKeyId = cert.extensions.getOrNull!(X509Extension.SubjectKeyIdentifier);
        if(!subjectKeyId.isNull)
        {
            subjectKeyHash = this.hashKey(subjectKeyId.get.keyIdentifier);
            if(this._certByHashedSubjectKey.getPtr(subjectKeyHash) !is null)
            {
                return Result.make(
                    X509StoreError.duplicateSubjectKeyId,
                    "certificate contains a subject key id that's already been used",
                    String2(
                        "subject key id was: ", subjectKeyId.get.keyIdentifier,
                        " (hashing to: ", subjectKeyHash, ")"
                    )
                );
            }

        }

        // Wait until all validation checks are done before storing the cert.
        if(!subjectKeyId.isNull)
            this._certByHashedSubjectKey[subjectKeyHash] = cert;
        this._certs.put(cert);
        return Result.noError;
    }

    private Result loadCert(Cert* cert) @nogc nothrow
    {
        import core.stdc.stdlib : free;

        import juptune.data.buffer : MemoryReader;
        import juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Certificate;
        import juptune.data.x509.asn1convert : x509FromAsn1;
        import juptune.data.asn1.decode.bcd.encoding 
            : Asn1ComponentHeader, asn1DecodeComponentHeader, asn1ReadContentBytes,
              Asn1Ruleset;

        bool success;
        scope(exit) if(!success)
        {
            (*cert).__xdtor();
            free(cert);
        }

        auto derMem = MemoryReader(cert.underlyingBytes.slice);

        Asn1ComponentHeader header;
        auto result = asn1DecodeComponentHeader!(Asn1Ruleset.der)(derMem, header);
        if(result.isError)
            return result;

        Certificate asn1Cert;
        result = asn1Cert.fromDecoding!(Asn1Ruleset.der)(derMem, header.identifier);
        if(result.isError)
            return result;

        result = x509FromAsn1(asn1Cert, cert.certificate);
        if(result.isError)
            return result;

        result = X509ExtensionStore.fromCertificate(cert.certificate, cert.extensions);
        if(result.isError)
            return result;

        success = true;
        return Result.noError;
    }
}

@("store.d - General megatest")
unittest
{
    import std.file : fileRead = read, exists;
    import juptune.core.util : resultAssert;

    X509CertificateStore store;

    void readCert(string path, bool isRootCert)
    {
        if(!path.exists) // Check if we're running from the build dir instead of the root dir (e.g. because of `meson test`).
            path = "../"~path;

        const bytes = cast(ubyte[])fileRead(path);
        store.loadFromCopyingDerBytes(bytes, hasImplicitTrust: isRootCert).resultAssert;
    }

    if(!exists("./data/test/asn1") && !exists("../data/test/asn1"))
    {
        import std.stdio : writeln;
        writeln("[SKIP] Cannot find ./data or ../data - juptune-unittest is being ran somewhere weird, skipping test.");
        return;
    }

    // NOTE: Currently can't test validation since I need to make certs that _haven't_ expired 2 decades ago.
    readCert("data/test/asn1/rfc5280-ref-certs/self-signed.cer", isRootCert: true);
    readCert("data/test/asn1/rfc5280-ref-certs/signed-rsa.cer", isRootCert: true);

    assert(store.getBySubjectKeyIdOrNull([0]) is null);
    assert(store._certs.length == 2);
    assert(store._certByHashedSubjectKey.length == 2);

    auto selfSigned = store.getBySubjectKeyIdOrNull([
        0x08, 0x68, 0xAF, 0x85, 0x33, 0xC8, 0x39, 0x4A, 0x7A, 0xF8, 
        0x82, 0x93, 0x8E, 0x70, 0x6A, 0x4A, 0x20, 0x84, 0x2C, 0x32,
    ]);
    assert(selfSigned !is null);
    assert(selfSigned.extensions.getOrNull!(X509Extension.BasicConstraints).get.ca);
}