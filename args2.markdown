With Ceno we are defining and implementing an interpretation of the Risc-V spec.

Ideally, we keep that very simple and straightforward.  As much as possible.  We don't want to be clever.  We don't want to be subtle.  We don't want to be tricky.  We want to be boring.

Alas, at the moment we are actually defining (at least) two interpretations of the Risc-V spec: one in the emulator, largely copied-and-pasted from Risc0, and one in the prover.

Those two ain't the same.  As Ming helpfully pointed out, some of my complaints actually only apply to our emulator, and it was naive of me to assume that our prover and our emulator speak the same language.  They don't.

My bold proposal is that we should make them speak the same language.  As much as possible, everything that's allowed (or banned) in the prover should be allowed (or banned) in the emulator, and vice versa.  They should behave the same way.

Writing a Risc-V emulator is fairly straightforward, especially if, like us, you don't have too wring out every last bit of performance out of this part of the system.  (Just to remind you, the majority of the time is spent in the prover, not the emulator.)

Writing a Risc-V prover is a whole different kettle of fish.  It's a lot more complicated, and a lot more subtle.  It's also a lot more important to get right.  I suggest we make both parts of the system speak the same language, and that we make the prover the master of that language.

Making prover and emulator speak obviously the same language helps with reviewing the constraints for correctness: 'just' check if they allow exactly the same behaviour as the emulator.  I say 'just' in scare quotes, because that's already hard enough.  But it's infinitely easier and less error prone than deliberately designing two different languages and then trying to figure out how they relate to each other, and which deviations are intentional and which are bugs.

https://github.com/scroll-tech/ceno/issues/539 is an interesting illustration of the difficulties here, but also how our recent efforts are already bearing fruit.  Nice work, @naure!
