# Example Ceno Application

This is an example repo for how a Ceno application with a guest and host support can look like.

You can find the guest in `guest` directory and the host in `host` directory. `cargo run` runs the guest
with the host.

In `elf` you find some support for building the guest.  Later this will likely move into a cargo plugin,
like SP1 and Risc0 are doing.
