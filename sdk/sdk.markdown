# SDK design

SDK stands for software development kit.  It encompasses everything a developer needs to build and run a guest program.  Specifically, that includes the build system, a standard library and other libraries, our runtime, the prover.

Let's sketch out a few different approaches to SDK design, concentrating on how guest code would look like.

## Input / Output

### Manual

This is what [Miden does](https://github.com/0xPolygonMiden/miden-vm/tree/main/miden#inputs--outputs).  The VM offers a few ways for guest programs to get input and produce output.  The low level mechanism are fine, and not to different from what we'd implement.

But they never built anything higher level around this: the SDK expects your host program to just somehow come up with the right [Merkle tree and tape](https://github.com/0xPolygonMiden/miden-vm/blob/main/miden/examples/merkle_store/merkle_store.inputs).

By itself, this model is pretty much useless for anything but toy examples.

### Client/server model

The client is the guest program, and the server is the host program.  From the point of view of the author of the guest program, the host program is like a server that you can send [RPC](https://en.wikipedia.org/wiki/Remote_procedure_call) requests to.

This model is conceptually relatively simple, but it tends to split your program into two parts: the client part, which runs on the guest, and the server part, which runs on the host.  That can be a bit awkward to keep in your head, and there's quite a bit of conceptual redundancy.

This style encourages the guest to prepare and send all the information necessary to identify a call to the server, instead of unlocking the full potential of non-determinism in the oracle model.

[Risc0 uses this model.](https://dev.risczero.com/api/0.20/zkvm/host-code-101)

### Unconstrained / constrained modes

This model can combine host and guest source code.  At a low level, your VM gets a special instruction to 'fork' execution.  When execution reaches the 'fork', we pause the original execution, make a clone of all the state, and proceed with the clone.  The clone runs outside of the constraints and its execution is not proven.  The clone can do anything, including calling out to the network, reading from disk, etc.  At the end, the clone can return a value to the original execution, which resumes and can use that value in its own proven computation.

As mentioned above, this model allows you to naturally mix host and guest code.  Most guest developers don't even need to be aware of what's happening: they are just calling a function to read from the network, and all the mode switching is handled by the SDK.

In this model it's really easy for the host code to have access to the full state of the guest code, without explicitly passing any information with the 'fork' call: it's all just available.

As a downside, becasue the host-code is also written in Risc-V, you need to add support for all the crazy stuff you want to do in your Risc-V emulator (or at least allow it to call out to third party programs).  This style also blows up the size of your guest ELF.

This model is inspired by SP1's 'unconstrained' mode. (But what they are actually doing is a more complicated mix of models.)

### Multi-stage computation

From the guest program developers point of view, this model looks like the unconstrained/constrained model.  But instead of embedding both code paths in the same Risc-V ELF, you use conditional compilation to generate two separate ELFs.

The first ELF has all the code, including the unconstrained parts.  It executes everything, and keeps track of the results of the unconstrained parts on a 'tape'.  The second ELF only has the constrained code, and whenever it hits a 'fork' instruction, it read consults the tape we prepared earlier.

In this model, the first ELF doesn't even have to run on Risc-V, it can run natively for all we care.  The only requirement is that it can produce a tape that the second ELF can read.  Running natively means that you can use all the libraries and tools that are available for your host platform, without our emulator having to know anything about this.

Specifically, you can run a full fledged debugger, without our emulator having to support it.

## Building

Both Risc0 and SP1 ship their own version of the Rust compiler.  (As far as I can tell.)  Those versions are quite out of date by now.  So I'd like to avoid that, if we can, and allow people to the stock Rust compiler.  We don't want to be in the business of maintaining a fork of the Rust compiler.

Ideally, I'd also want to make it easy for people to run eg C and C++ programs, too.  If we can make the stock Rust compiler work, it's more likely that interested parties can make other compilers work as well.

Both Risc0 and SP1 use their own cargo plugins.  I think that's mostly because they use their own compilers.  But we can investigate if there are other pressing reasons.  (They also use these plugins for configuring cargo and the compiler; that's something we are doing right now with just normal cargo configuration files and command line arguments.)
