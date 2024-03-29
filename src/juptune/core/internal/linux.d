/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */
module juptune.core.internal.linux;

version(linux):

import juptune.core.ds   : String2, Array;
import juptune.core.util : Result;

import core.stdc.stdio              : sscanf;
import core.stdc.string             : strlen;
import core.sys.posix.signal        : sigaction, sigaction_t, SIG_DFL;
import core.sys.posix.sys.utsname   : utsname, uname;
import core.sys.linux.string        : strerror_r;

enum LINUX_ERROR_BUFFER_SIZE = 1024; // https://man7.org/linux/man-pages/man3/strerror.3.html#NOTES

struct LinuxKernal
{
    int major;
    int minor;
    int patch;
}
shared const LinuxKernal g_linuxKernal;

shared static this()
{
    utsname kernalInfo;
    uname(&kernalInfo);
    sscanf(&kernalInfo.release[0], "%d.%d.%d", &g_linuxKernal.major, &g_linuxKernal.minor, &g_linuxKernal.patch);
}

import core.sys.linux.errno : ECANCELED;
/// Result.make requires an enum type for strong typing,
/// however I'm not going to make let alone maintain a list of all
/// linux errors, so we'll get by with just `cast(LinuxError)` and `cast(int)` shennanigans if
/// the error code is truly needed directly from a Result - which chances are unlikely to be the case.
enum LinuxError 
{ 
    none = 0,
    cancelled = ECANCELED, // Useful to detect in user code, so given a direct enum value.
}

alias SignalHandler = void delegate() nothrow shared;
void linuxSetSignalHandler(int SignalNum)(SignalHandler handler) @nogc nothrow
{
    static shared SignalHandler g_handleForNum;
    g_handleForNum = handler; // Ensure we keep a GC-accessible ref to the delegate.

    sigaction_t act;
    act.sa_handler = (int _){
        g_handleForNum();
    };

    const result = sigaction(SignalNum, &act, null);
    assert(result == 0, "sigaction somehow failed");
}

void linuxResetSignalHandler(int SignalNum)() @nogc nothrow
{
    sigaction_t act;
    act.sa_handler = SIG_DFL;

    const result = sigaction(SignalNum, &act, null);
    assert(result == 0, "sigaction somehow failed");
}

/++
 + Converts a errno value into a `Result`.
 +
 + Params:
 +  staticMessage = A static message used to provide context to the user.
 +  errnum = The errno value. If this is negative, then it is converted to its absolute value.
 +
 + Throws:
 +  Always a `LinuxError`.
 +
 + Returns:
 +  A `Result` containing a `LinuxError`.
 +
 + See_Also:
 +  `LinuxError`
 + ++/
Result linuxErrorAsResult(string staticMessage, int errnum) @nogc nothrow
{
    if(errnum < 0)
        errnum = -errnum;

    Array!char msg;
    msg.length = LINUX_ERROR_BUFFER_SIZE;
    msg[0..$] = '\0';

    scope mutablePtr = cast(char*)msg.ptr; // Breaks the type system; but is safe to do this.
    const staticMsg = strerror_r(errnum, mutablePtr, msg.length-1); // - 1 so we can ensure a null terminator // @suppress(dscanner.suspicious.length_subtraction)

    // Sometimes strerror_r returns a static string, sometimes it stores it in the buffer. What beautiful API design...
    if(staticMsg !is null && staticMsg !is mutablePtr)
    {
        msg.length = strlen(staticMsg);
        mutablePtr[0..msg.length] = staticMsg[0..msg.length];
    }
    else
        msg.length = strlen(msg.ptr);

    return Result.make(cast(LinuxError)errnum, staticMessage, String2.fromDestroyingArray(msg));
}