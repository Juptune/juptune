module juptune.data.asn1.generated.raw.PKIXAttributeCertificate_1_3_6_1_5_5_7_0_12;
static import PKIX1Explicit88_1_3_6_1_5_5_7_0_18 = juptune.data.asn1.generated.raw.PKIX1Explicit88_1_3_6_1_5_5_7_0_18;
static import PKIX1Implicit88_1_3_6_1_5_5_7_0_19 = juptune.data.asn1.generated.raw.PKIX1Implicit88_1_3_6_1_5_5_7_0_19;

static import tcon = std.typecons;
static import asn1 = juptune.data.asn1.decode.bcd.encoding;
static import jres = juptune.core.util.result;
static import jbuf = juptune.data.buffer;
static import jstr = juptune.core.ds.string2;
static import utf8 = juptune.data.utf8;

asn1.Asn1ObjectIdentifier id_pe_ac_auditIdentity(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 1, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_pe_aaControls(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 1, 6, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_pe_ac_proxying(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 1, 10, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_ce_targetInformation(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        29, 55, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_aca(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 10, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_aca_authenticationInfo(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 10, 1, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_aca_accessIdentity(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 10, 2, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_aca_chargingIdentity(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 10, 3, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_aca_group(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 10, 4, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_aca_encAttrs(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        6, 1, 5, 5, 7, 10, 6, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(1, 3, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_at_role(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        4, 72, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}

asn1.Asn1ObjectIdentifier id_at_clearance(
) @nogc nothrow
{
    asn1.Asn1ObjectIdentifier mainValue;
    static immutable ubyte[] mainValue__value = [
        1, 5, 55, 
    ];
    mainValue = asn1.Asn1ObjectIdentifier.fromUnownedBytes(2, 5, mainValue__value);
    return mainValue;

}
