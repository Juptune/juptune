# Overview

juptune is an @nogc-first, multithreaded, highly configurable async I/O library that aims to be a batteries-included foundation for developing modern web-based applications.

This project is currently in a _very_ early state; almost certainly has major issues, and just generally isn't ready for anything beyond proof of concept stuff.

Only Linux is supported, and that likely won't ever change.

**I currently don't accept MRs for this project - really small things like tiny bug fixes may be merged in however**

# Features

* `@nogc` first API, but with `@gc` alternatives for comfort.
* Code is entirely `nothrow` (except maybe for some `@gc` stuff), uses the core `Result` struct for error handling.
* `juptune.core` has a bunch of `@nogc` utilities, such as datastructures and more importantly the `Result` type used for Go style error handling.
* `juptune.event` provides the multithreaded event loop (including fibers); io_uring interface, as well as slightly higher level constructs for generic I/O.
* `juptune.http` provides HTTP1 client & server implementations.

## Core

* Basic dynamic array implementation with tweakable allocation parameters.
* Robin hood (w/ backshift) hashmap with tweakable allocation parameters.
* String implementation with small string optimisation.
* ANSI utility package for dealing with colours.
* Data conversion.
* A `Result` type that stores strongly typed errors - used for `@nogc` error handling.

## Event

* Entirely designed around io_uring's completion model, with small openings for other platform support.
* `@nogc` and `@gc` fibers + threads that can be used side-by-side.
* The io_uring driver; fiber allocator, and the event loop can all be individually configured.
* Primitive types for working with common I/O file descriptors.
* IPv4 and IPv6 utilities (may move to core, not too sure yet).

## HTTP

* HTTP1 support. HTTP2 and (especially) HTTP3 are currently pipe dreams.
* Low-level primitive reader and writer that provides structured access to reading/writing each part of a HTTP1 message.
* A full validating URI (RFC 3986) parser, as well as encoding/decoding utilities.

# Threading model

Juptune currently models itself around having each thread segregated from eachother - each thread has its own fiber pool; uses its own thread local storage (a built-in aspect of D) for certain things, and generally they run independently from one another.

Each thread is responsible for creating its own fibers. In other words, thread A cannot create a fiber that runs in thread B. 

In the future I'd like to look more closely into cross-thread communication; make cross-fiber communication less of a pain, and introduce something like worker threads (or even a better abstraction - thread groups) to make offloading fibers onto other threads possible.

Currently all of missing features mentioned in the above paragraph have to be homebrewed by an application.

# Roadmap/Wishlist

This is an ever changing list of stuff I want to work on. Whether I get around to it is another question...

* Higher level HttpClient - likely the next feature I'll implement.
* TLS support (and then updating the HTTP stuff to be able to use it) - The idiot in me wants to implement it myself for fun, but it's probably better if I just use something like s2n-tls if I want people to actually use this library eventually.
* A web framework
* HTTP2 support - I think it's doable by my mortal hands, but really out of scope for me right now.
* HTTP3 support - lol, maybe if the linux kernal gets native QUIC support.
* Postgres package that supports `juptune.event`
* Cloud provider SDKs - Probably a pipe dream, but once the HTTP support is more matured then auto-generating the SDKs _may_ become a possibility.
* A strong testing package - You'll notice most unittests have a name, however I only use the built-in D test runner right now, something I want to change.
* gRPC support - requires HTTP2 stuff ;_;
* gRPC-web support?
* Logging package.

# Examples

Examples live under the `./examples` folder:

* basic-meson-project: A small barebones meson-based project that uses Juptune.
* http-echo-low-level: A HTTP Echo server using the low level HTTP API.
* http-hello-world-hardcoded: A TCP server that serves a hardcoded HTTP response.