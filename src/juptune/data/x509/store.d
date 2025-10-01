/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.data.x509.store;

import juptune.core.util : Result;
import juptune.data.x509.asn1convert : X509Certificate, X509Extension;

enum X509StoreError
{
    none,
    extensionAlreadySet
}

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
                    enum Found = true;
                    return i;
                }
            }

            static if(!__traits(compiles, { bool b = Found; }))
                static assert(false, "Type "~T.stringof~" is not a valid extension type");
        }
    }

    @disable this(this);

    static Result fromCertificate(ref X509Certificate cert, scope ref typeof(this) store)
    {
        import juptune.data.x509.asn1convert : x509HandleExtension;

        store = typeof(this).init;
        if(cert.extensions.isNull)
            return Result.noError;

        return cert.extensions.get.get().foreachElementAutoGC((element){
            X509Extension.SumT ext;
            auto result = x509HandleExtension(element, ext);
            if(result.isError)
                return result;

            import std.sumtype : match;
            return ext.match!(
                (X509Extension.Unknown unknown) { store.addUnknown(unknown); return Result.noError; },
                (e) { return store.set(e); }
            );
        });
    }

    void addUnknown(X509Extension.Unknown unknown) @nogc nothrow
    {
        this._unknowns.put(unknown);
    }

    ref const(Array!(X509Extension.Unknown)) getUnknownExtensions() @nogc nothrow const => this._unknowns;

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

    Nullable!T get(T)() => this._extensions[indexOf!T];
}