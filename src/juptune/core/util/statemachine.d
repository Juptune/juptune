/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 * Author: Bradley Chatha
 */

module juptune.core.util.statemachine;

template StateMachineTypes(alias StateEnum, alias TransitionContext)
{
    alias Transition = StateTransition!(StateEnum, TransitionContext);
    alias Table(alias Transitions) = StateTransitionTable!(Transition, Transitions);
    alias Static(alias Transitions) = StateMachineStatic!(StateEnum, TransitionContext, Transitions);
}

struct StateTransition(alias StateEnum, alias TransitionContext)
{
    alias IsAllowed = bool function(scope ref TransitionContext) @safe @nogc nothrow;

    StateEnum from;
    StateEnum to;
    IsAllowed isAllowed;

    this(StateEnum from, StateEnum to, IsAllowed isAllowed = null)
    in(from != to, "from and to must be different")
    {
        this.from = from;
        this.to = to;
        this.isAllowed = isAllowed;
    }

    bool isAllowedSafe(scope ref TransitionContext context) @safe @nogc nothrow
    {
        return this.isAllowed is null ? true : this.isAllowed(context);
    }
}

struct StateTransitionTable(alias Transition, alias Transitions)
{
    import std.conv : convTo = to;

    template getTransition(alias from, alias to)
    {
        alias getTransition = noreturn;

        static foreach(transition; Transitions)
        {
            static if (transition.from == from && transition.to == to)
            {
                static if(!__traits(compiles, _transitionFound))
                {
                    enum _transitionFound = true;
                    getTransition = transition;
                }
                else static assert(false, "Multiple transitions from " ~ from.convTo!string ~ " to " ~ to.convTo!string ~ " are defined"); // @suppress(dscanner.style.long_line)
            }
        }
    }
}

struct StateMachineStatic(
    alias StateEnum, 
    alias TransitionContext,
    alias Transitions,
)
{
    import std.conv : convTo = to;
    import std.traits : isPointer;

    alias Transition = StateTransition!(StateEnum, TransitionContext);
    alias Table = StateTransitionTable!(Transition, Transitions);

    static assert(is(StateEnum == enum), "StateEnum must be an enum");
    static assert(is(TransitionContext == struct) || isPointer!TransitionContext, "TransitionContext must be a struct or pointer. Use void* if you don't need a context"); // @suppress(dscanner.style.long_line)
    static assert(is(typeof(Transitions) == Transition[]), "Transitions must be a StateTransition array"); // @suppress(dscanner.style.long_line)

    private
    {
        StateEnum state;
    }

    @safe @nogc nothrow:

    @disable this(this); // likely a bug if this struct is copied instead of referenced.

    this(StateEnum initialState)
    {
        this.state = initialState;
    }

    bool transition(StateEnum from, StateEnum to)(scope ref TransitionContext context)
    {
        alias Transition = Table.getTransition!(from, to);
        static assert(!is(Transition == noreturn), "No transition exists from " ~ from.convTo!string ~ " to " ~ to.convTo!string); // @suppress(dscanner.style.long_line)

        static if(Transition.isAllowed is null)
        {
            this.state = to;
            return true;
        }
        else
        {
            if(Transition.isAllowed(context))
            {
                this.state = to;
                return true;
            }
            return false;
        }
    }

    void mustTransition(StateEnum from, StateEnum to)(scope ref TransitionContext context)
    {
        enum ErrorString = "Transition from " ~ from.convTo!string ~ " to " ~ to.convTo!string ~ " was not allowed";

        const couldTransition = this.transition!(from, to)(context);
        if(!couldTransition)
            assert(false, ErrorString);
    }

    // TODO: This function returns a bool to make it easier to use with `in` guards.
    bool mustBeIn(StateEnum state)
    {
        if(this.state != state)
        {
            debug // Allows us to bypass @nogc so we can provide a better error message
            {
                import std.exception : assumeWontThrow;
                assert(false, "State must be " ~ state.convTo!string.assumeWontThrow ~ " but was " ~ this.state.convTo!string.assumeWontThrow); // @suppress(dscanner.style.long_line)
            } 
            else assert(false, "State machine is not in expected state");
        }

        return true;
    }

    bool isIn(StateEnum state)
    {
        return this.state == state;
    }

    version(unittest) void forceState(StateEnum state)
    {
        this.state = state;
    }
}
///
@("StateMachineStatic - basic usage")
unittest
{
    static enum State
    {
        hop,
        skip,
        jump,
    }

    struct Context
    {
        int x;
    }

    alias Types = StateMachineTypes!(State, Context);
    alias Machine = Types.Static!([
        Types.Transition(State.hop, State.skip),
        Types.Transition(State.skip, State.jump, (ref ctx) => ctx.x > 10),
    ]);

    alias Table = Machine.Table;
    static assert(Table.getTransition!(State.hop, State.skip) == Types.Transition(State.hop, State.skip));
    static assert(is(Table.getTransition!(State.skip, State.skip) == noreturn));

    auto context = Context(0);
    auto machine = Machine(State.hop);

    import std.random : uniform;
    machine.mustBeIn(State.hop);
    machine.mustTransition!(State.hop, State.skip)(context);
    machine.mustBeIn(State.skip);
    while(!machine.transition!(State.skip, State.jump)(context))
        context.x += uniform(1, 10);
    machine.mustBeIn(State.jump);

    static assert(!__traits(compiles, machine.transition!(State.jump, State.hop)(context)));
}