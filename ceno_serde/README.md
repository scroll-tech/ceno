## Ceno Serde

This crate hosts the word-addressed serializer/deserializer that our guest programs use.

The implementation is adapted from the `openvm` crate's serde module:
<https://github.com/scroll-tech/openvm/tree/main/crates/toolchain/openvm/src/serde>,
which is distributed under the MIT/Apache-2.0 licenses.

We copied the original files into this standalone crate so other parts of Ceno
can depend on the serializer without pulling in the rest of OpenVM.
