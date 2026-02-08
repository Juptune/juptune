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
    wrongPemLabel,          /// A certificate within a PEM encoded file contains the wrong label.
    noCertificates,         /// Edge case error when no certificates are provided for an operation where at least one certificate is required.
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
 +
 + Lifetimes:
 +  This store is mainly designed for higher level use, and as such it will freely allocate memory.
 +
 +  This store will always create copies of any input data. This means any resulting output will have its lifetime tied
 +  to the store itself. So as long as `X509CertificateStore` stays alive, all of its output will stay alive.
 +
 + Thread Safety:
 +  Currently this store is _not_ thread safe. However once Juptune's event loop has been refactored - ideally with a built-in concept of
 +  mutexes - then thread safety will likely be implemented either directly or indirectly.
 +
 +  For now it's recommended to:
 +   1. Perform all loads at program start.
 +   2. ONLY use validation functions from multiple threads.
 +   3. (The above _should_ be thread safe for a while).
 +
 +  Or:
 +   1. Use an external mutex solution - this isn't ideal since it won't integrate properly with Juptune's event loop.
 +
 +  Or:
 +   1. Just make one store per thread.
 + ++/
struct X509CertificateStore
{
    import juptune.core.ds : Array, HashMap, String;

    /// An aggregate type storing a bunch of information about an x.509 certificate.
    static struct Cert
    {
        X509Certificate certificate;
        X509ExtensionStore extensions;
        
        private Array!ubyte underlyingBytes;

        @disable this(this);
    }

    static struct SecurityPolicy
    {
        /// Please see the documentation for `validateChainFromCopyingDerBytes`.
        bool allowSelfSignedChain = false;

        @safe @nogc nothrow:

        typeof(this) withAllowSelfSignedChain(bool allow) return { this.allowSelfSignedChain = allow; return this; } // @suppress(dscanner.style.long_line)
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
     + Loads a certificate bundle from the given PEM encoded data.
     +
     + Notes:
     +  This function is not fully atomic (yet at least), if a certificate generates an error, any previous certificates
     +  will have been succesfully loaded into the store, and any following certificates will not be loaded.
     +
     +  Since unfortunately not all certificates in a bundle will be DER encoded (but instead BER), you may set
     +  `ignoreAsn1DecodingErrors` to true in order to continue loading certificates even if some certificates in the bundle
     +  are not DER encoded.
     +
     +  This function does not expect nor detect certificate chains within the given bundle - it will load (and optionally validate)
     +  all certificates as individual, standalone certificates.
     +
     +  Data from `pem` is copied - the caller is allowed to free/reuse `pem` after this function without fear.
     +
     + Params:
     +  pem                         = The raw PEM encoding.
     +  ignoreAsn1DecodingErrors    = If true, then any error of type `Asn1DecodeError` will be completely ignored.
     +  hasImplicitTrust            = If true, then the certificates will not be validated. If false, then the certificates will be validated.
     +
     + Throws:
     +  Anything that `loadFromCopyingDerBytes` can throw.
     +
     +  Anything that `PemParser.parseNext` can throw.
     +
     +  `X509StoreError.wrongPemLabel` if any item within the PEM data is not a "CERTIFICATE".
     + 
     + Returns:
     +  A `Result` indicating if an error occurred or not.
     + ++/
    Result loadBundleFromPem(
        scope const(char)[] pem, 
        bool ignoreAsn1DecodingErrors = false,
        bool hasImplicitTrust = false,
    ) @nogc nothrow
    in(pem.length > 0, "pem is empty")
    {
        import juptune.core.ds : ArrayNonShrink;
        import juptune.asn1.decode.bcd.encoding : Asn1DecodeError;
        import juptune.data.pem : PemParser;

        ArrayNonShrink!ubyte buffer;
        auto parser = PemParser(pem);
        while(!parser.eof)
        {
            auto result = parser.parseNext(
                onStart: (label){
                    if(label != "CERTIFICATE")
                    {
                        return Result.make(
                            X509StoreError.wrongPemLabel,
                            "expected data boundary in PEM to have label CERTIFICATE",
                            String("got label '", label, "'")
                        );
                    }

                    return Result.noError; 
                },
                onData: (scope data){
                    buffer.put(data);
                    return Result.noError; 
                },
                onEnd: () => Result.noError,
            );
            if(result.isError)
                return result;

            result = this.loadFromCopyingDerBytes(buffer.slice, hasImplicitTrust: hasImplicitTrust);
            if(result.isError)
            {
                if(!(result.isErrorType!Asn1DecodeError && ignoreAsn1DecodingErrors))
                    return result;
            }

            buffer.length = 0;
        }

        return Result.noError;
    }

    /++
     + A helper function that combines `PemParser` and `validateChainFromCopyingDerBytes` together. Please
     + refer to each of their documentation for any real details.
     +
     + Notes:
     +  Certificates in PEM may not actually be DER encoded (but instead BER). Currently this code
     +  hard assumes that the certificate is DER encoded.
     +
     + Throws:
     +  Anything that `PemParser.parseNext` can throw.
     +
     +  Anything that `validateChainFromCopyingDerBytes` can throw.
     +
     +  `X509StoreError.wrongPemLabel` if any item within the PEM data is not a "CERTIFICATE".
     +
     + Returns:
     +  A `Result` indicating if an error occurred or not.
     +
     + See_Also:
     +  `PemParser.parseNext`, `validateChainFromCopyingDerBytes`.
     + ++/
    Result validateChainFromPem(scope const(char)[] pem, const SecurityPolicy policy)
    {
        import juptune.core.ds : ArrayNonShrink;
        import juptune.data.pem : PemParser;

        ArrayNonShrink!ubyte buffer;
        auto parser = PemParser(pem);

        return this.validateChainFromCopyingDerBytes(
            (scope out derBytes, scope out success){
                if(parser.eof)
                    return Result.noError;

                buffer.length = 0;
                auto result = parser.parseNext(
                    onStart: (label){
                        if(label != "CERTIFICATE")
                        {
                            return Result.make(
                                X509StoreError.wrongPemLabel,
                                "expected data boundary in PEM to have label CERTIFICATE",
                                String("got label '", label, "'")
                            );
                        }

                        return Result.noError; 
                    },
                    onData: (scope data){
                        buffer.put(data);
                        return Result.noError; 
                    },
                    onEnd: () => Result.noError,
                );
                if(result.isError)
                    return result;
                
                derBytes = buffer.slice;
                success = true;
                return Result.noError;
            },
            policy: policy,
            reverseChain: true
        );
    }

    /++
     + Validates a chain of certificates (or a "chain" with a single certificate) from the given raw DER encoded bytes.
     + These certificates are not loaded into the store, and are immediately freed upon exit of this function.
     +
     + Notes:
     +  When the `nextInChain` parameter returns `true`, it must populate its parameter with a byte slice of a DER encoded ASN.1 x.509 `Certificate` structure.
     +  This memory is immediately copied, so `nextInChain` is free to reuse any internal buffers it exposes to this function.
     +
     +  When `nextInChain` is unable to provide another certificate, it must return `false`. It should leave its parameter as `null` in this case.
     +
     + Security Policy:
     +  **allowSelfSignedChain** = If the first certificate in the chain is self-signed; this value is `false`, and the self-signed certificate has not
     +                             been previously loaded into the store, then the chain is rejected.
     +                             However if this value is `true`, the chain will continue to be validated using the first certificate as the trust anchor
     +                             if the first certificate is self-signed.
     +
     + Params:
     +  nextInChain  = A user-provided callback for accessing the next certificate in the chain, please see Notes for important info.
     +  policy       = The security policy to apply to this function, please see "Security Policy" for important info.
     +  reverseChain = If true, then the chain will be reversed before being validated. This is useful for when `nextInChain` is handling PEM input,
     +                 as PEM certificates store chains in reverse order.
     + Throws:
     +  Anything that the underlying ASN.1 decoder functions can throw (`Asn1DecodeError`).
     +
     +  Anything that `x509FromAsn1` can throw.
     +
     +  Anything that `X509ExtensionStore.fromCertificate` can throw.
     +
     +  Anything that `x509ValidatePath` can throw.
     +
     +  `X509StoreError.trustAnchorNotFound` if a trust anchor could not be determined, and if the first certificate in the chain could not
     +  be used as the trust anchor (see Security Policy).
     +
     +  `X509StoreError.noCertificates` if `nextInChain` doesn't generate any certificates.
     +
     + Returns:
     +  A `Result` indicating if an error occurred or not.
     + ++/
    alias validateChainFromCopyingDerBytes = validateChainFromCopyingDerBytesImpl!(Result delegate(scope out const(ubyte)[] derBytes, scope out bool success) @nogc nothrow); // @suppress(dscanner.style.long_line)
    alias validateChainFromCopyingDerBytesGC = validateChainFromCopyingDerBytesImpl!(Result delegate(scope out const(ubyte)[] derBytes, scope out bool success)); // @suppress(dscanner.style.long_line)

    private Result validateChainFromCopyingDerBytesImpl(NextT)(
        scope NextT nextInChain, 
        const SecurityPolicy policy, 
        bool reverseChain = false
    )
    in(nextInChain !is null, "nextInChain is null")
    {
        import core.stdc.stdlib : calloc, free;
        import core.exception : onOutOfMemoryErrorNoGC;

        Array!(Cert*) stagingCerts;

        scope(exit) foreach(cert; stagingCerts)
        {
            (*cert).__xdtor();
            free(cert);
        }

        bool success;
        const(ubyte)[] derBytes;
        
        auto result = nextInChain(derBytes, success);
        if(result.isError)
            return result.wrapError("when fetching first in chain:");

        while(success)
        {
            auto certPtr = cast(Cert*)calloc(1, Cert.sizeof);
            if(certPtr is null)
                onOutOfMemoryErrorNoGC();
            certPtr.underlyingBytes.put(derBytes);

            result = this.loadCert(certPtr);
            if(result.isError)
                return result.wrapError("when loading certificate in chain:");

            stagingCerts.put(certPtr);

            result = nextInChain(derBytes, success);
            if(result.isError)
                return result.wrapError("when fetching next in chain:");
        }

        if(stagingCerts.length == 0)
            return Result.make(X509StoreError.noCertificates, "no certificates were provided by nextInChain?");

        return (stagingCerts.length > 1) 
            ? this.validateCertChain(stagingCerts.slice, policy, reverseChain).wrapError("when validating cert chain:")
            : this.validateSingleCert(stagingCerts[0]).wrapError("when validating single cert:");
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

    private Result validateCertChain(scope Cert*[] chain, const SecurityPolicy policy, bool reverseChain) @nogc nothrow
    in(chain.length > 0, "chain is empty?")
    in(chain.length > 1, "chain is only one cert long?")
    {
        import juptune.core.ds : ArrayNonShrink;
        import juptune.data.x509.validation : x509IsSelfSigned, x509ValidatePath, X509CertificateValidationInfo;

        auto firstCert = chain[reverseChain ? chain.length-1 : 0]; // @suppress(dscanner.suspicious.length_subtraction)

        // Find the trust anchor, or fallback to using a self-signed cert if allowed.
        Cert* trustAnchor;
        auto result = this.findTrustAnchor(firstCert, trustAnchor);
        if(result.isError(X509StoreError.trustAnchorNotFound) && policy.allowSelfSignedChain)
        {
            bool isSelfSigned;
            auto selfSignedResult = x509IsSelfSigned(
                X509CertificateValidationInfo(&firstCert.certificate, &firstCert.extensions),
                isSelfSigned
            );
            if(selfSignedResult.isError)
                return selfSignedResult;

            if(!isSelfSigned)
                return result.wrapError("first certificate in chain is also not self signed:");
                
            trustAnchor = firstCert;
            chain = (reverseChain) ? chain[0..$-1] : chain[1..$];
        }
        else if(result.isError)
            return result.wrapError("when finding trust anchor:");

        // Build up the chain, reversing it if requested.
        ArrayNonShrink!X509CertificateValidationInfo info;
        info.reserve(chain.length);

        if(reverseChain)
        {
            import std.range : retro;
            foreach(cert; chain.retro)
                info.put(X509CertificateValidationInfo(&cert.certificate, &cert.extensions));
        }
        else
        {
            foreach(cert; chain)
                info.put(X509CertificateValidationInfo(&cert.certificate, &cert.extensions));
        }

        // Perform validation.
        const pointInTimeUtc = this.currTime();
        return x509ValidatePath(
            info.slice, 
            X509CertificateValidationInfo(&trustAnchor.certificate, &trustAnchor.extensions), 
            pointInTimeUtc
        ).wrapError("when validating path:");
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
                    String("authorityKeyIdentifier was: ", authKeyId.get.keyIdentifier)
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
                    String(
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
        import juptune.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18 : Certificate;
        import juptune.data.x509.asn1convert : x509FromAsn1;
        import juptune.asn1.decode.bcd.encoding 
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

private __gshared X509CertificateStore g_platformDefaultStore;
shared static this()
{
    import std.file : readText, exists;
    import juptune.core.util : resultAssert;

    version(linux)
    {
        auto bundlePath = "/etc/ssl/ca-bundle.pem";
        if(!exists(bundlePath))
            bundlePath = "/etc/ssl/certs/ca-certificates.crt";

        if(exists(bundlePath))
        {
            const pem = readText(bundlePath);
            g_platformDefaultStore.loadBundleFromPem(pem, ignoreAsn1DecodingErrors: true, hasImplicitTrust: true).resultAssert; // @suppress(dscanner.style.long_line)
        }
    }
    else static assert(false, "TODO: add platform");
}

/++
 + Retrieves the default certificate store for the host platform.
 +
 + Notes:
 +  This store is actually loaded during application startup, so this function is very cheap to call.
 +
 +  While the return value isn't marked as const (since D's const is a massive PITA to get correct), please
 +  note that **the return value must never have new certificates loaded into it** as this instance is shared
 +  across all threads... and well, X509CertificateStore currently isn't thread-safe.
 +
 +  _Only_ stick to using this for the validateChain functionality.
 +
 + Returns:
 +  A pointer to the global X509CertificateStore instance, with the current platform's default certificates already loaded in.
 + ++/
X509CertificateStore* x509GetPlatformDefaultStore() @nogc nothrow
{
    return &g_platformDefaultStore;
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