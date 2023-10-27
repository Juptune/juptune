version(unittest) void main(){}
else void main()
{
    import juptune.core.ds : HashMap;
    import std : to, writeln;

    HashMap!(string, int) map;
    foreach(i; 0..100)
        map["key" ~ i.to!string] = i;

    foreach(kvp; map.byKeyValue)
        writeln(kvp.key, " => ", kvp.value);
}