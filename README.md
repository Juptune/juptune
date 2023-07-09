# Overview

juptune-event is an @nogc-first, multithreaded, highly configurable async library that aims to be a high-performance base for further foundational libraries to be built off of, such as a HTTP server; database drivers, and so on.

**I currently don't accept MRs for this project.**

# Features

* Entirely designed around io_uring's completion model, though is partially designed to support drivers for other platforms.
* `@nogc` fibers
* `@gc` fibers and threads that can easily mix with @nogc code
* `@nogc` first API, but with `@gc` alternatives for comfort
* The io_uring driver; fiber allocator, and the event loop can all be individually configured.
* Explicit control over whether a fiber is limited to the same event loop thread, or if it can move between threads (moving between threads not yet implemented).
* Code is entirely `nothrow`, uses juptune-core's `Result` struct for error handling.

# Threading model

TODO

# Examples

TODO