Here's some background first.  I'll reply to your specific points in a second comment.

Risc0 has questionable design choices.  We took `DecodedInstruction` straight from Risc0. `InsnRecord`, which as far as I can tell we wrote ourselves, is a lot saner.

If you have a look at the [RiscV spec](https://riscv.org/wp-content/uploads/2017/05/riscv-spec-v2.2.pdf), you'll see on page 12 how some of the various instruction formats are laid out.  Specifically, you see that all instruction formats define various fields and how they are encoded in the instruction word.

Some formats have common fields.  But in general, the set of fields differs between types, and bits are re-used for different fields in different formats.  Especially the immediate field is encoded in whatever bits were left over.  (If you go further down the spec, you'll see a few more other instruction formats described.)

SP1 is an example of a reasonably sane implementation of that design.  They use the [`rrs-lib`](https://crates.io/crates/rrs-lib) crate.  You can find definitions like this in `rrs-lib`:

```rust
pub struct RType {
    pub funct7: u32,
    pub rs2: usize,
    pub rs1: usize,
    pub funct3: u32,
    pub rd: usize,
}
```

```rust
pub struct IType {
    pub imm: i32,
    pub rs1: usize,
    pub funct3: u32,
    pub rd: usize,
}
```

```rust
pub struct ITypeShamt {
    pub funct7: u32,
    pub shamt: u32,
    pub rs1: usize,
    pub funct3: u32,
    pub rd: usize,
}
```

Those are the fields that the spec defines for the different formats.  SP1 then goes on and converts to an internal format:

```rust
/// RISC-V 32IM Instruction.
///
/// The structure of the instruction differs from the RISC-V ISA. We do not encode the instructions
/// as 32-bit words, but instead use a custom encoding that is more friendly to decode in the
/// SP1 zkVM.
#[derive(Clone, Copy, Serialize, Deserialize)]
pub struct Instruction {
    /// The operation to execute.
    pub opcode: Opcode,
    /// The first operand.
    pub op_a: u8,
    /// The second operand.
    pub op_b: u32,
    /// The third operand.
    pub op_c: u32,
    /// Whether the second operand is an immediate value.
    pub imm_b: bool,
    /// Whether the third operand is an immediate value.
    pub imm_c: bool,
}
```

The format they use in their proofs looks very similar.  So far so sane.  (Note also how they use `pub` fields throughout.)

Now let's have a look at Risc0's `risc0/circuit/rv32im/src/prove/emu/rv32im.rs`:

```rust
impl DecodedInstruction {
    fn new(insn: u32) -> Self {
        Self {
            insn,
            top_bit: (insn & 0x80000000) >> 31,
            func7: (insn & 0xfe000000) >> 25,
            rs2: (insn & 0x01f00000) >> 20,
            rs1: (insn & 0x000f8000) >> 15,
            func3: (insn & 0x00007000) >> 12,
            rd: (insn & 0x00000f80) >> 7,
            opcode: insn & 0x0000007f,
        }
    }
```

They define a bunch of arbitrary fields, some of which share names and positions with some fields in some formats in the spec.  But they are all jumbled into one incoherent mess, instead of being separated into the different formats.  (Some other fields are completely made up, and don't appear anywhere in the spec.  And the spec also has some instructions where fields of the same name are encoded in different bits.)

Now to go from that mess to the fields that the spec wants for the different formats, they need to do a second round of bit fiddling:

```rust
    fn imm_b(&self) -> u32 {
        (self.top_bit * 0xfffff000)
            | ((self.rd & 1) << 11)
            | ((self.func7 & 0x3f) << 5)
            | (self.rd & 0x1e)
    }

    fn imm_i(&self) -> u32 {
        (self.top_bit * 0xfffff000) | (self.func7 << 5) | self.rs2
    }

    fn imm_s(&self) -> u32 {
        (self.top_bit * 0xfffff000) | (self.func7 << 5) | self.rd
    }

    fn imm_j(&self) -> u32 {
        (self.top_bit * 0xfff00000)
            | (self.rs1 << 15)
            | (self.func3 << 12)
            | ((self.rs2 & 1) << 11)
            | ((self.func7 & 0x3f) << 5)
            | (self.rs2 & 0x1e)
    }

    fn imm_u(&self) -> u32 {
        self.insn & 0xfffff000
    }
}
```

For good measure, their emulator does a **third** round of bit fiddling.

```rust
InsnKind::SLLI => rs1 << (imm_i & 0x1f),
InsnKind::SRLI => rs1 >> (imm_i & 0x1f),
InsnKind::SRAI => ((rs1 as i32) >> (imm_i & 0x1f)) as u32,
```

SP1 does a **single** round all via `rrs`, and in a way that even someone as simple minded as me can understand as a straightforward implementation of the spec.

Alas, we copied our decoding from them, and not SP1.  (But notice how our `InsnRecord` resembles SP1's `Instruction` much more than it does anything in Risc0.)

Let's move on to self-modifying code, and have a look at Risc0's `step` function in `risc0/circuit/rv32im/src/prove/emu/rv32im.rs` ((the origin of our `ceno_emul/src/rv32im.rs`):

```rust
pub fn step<C: EmuContext>(&mut self, ctx: &mut C) -> Result<()> {
    let pc = ctx.get_pc();

    if !ctx.check_insn_load(pc) {
        ctx.trap(TrapCause::InstructionAccessFault)?;
        return Ok(());
    }

    let word = ctx.load_memory(pc.waddr())?;
    if word & 0x03 != 0x03 {
        ctx.trap(TrapCause::IllegalInstruction(word))?;
        return Ok(());
    }

    let decoded = DecodedInstruction::new(word);
    let insn = self.table.lookup(&decoded);
    ctx.on_insn_decoded(&insn, &decoded);

    if match insn.category {
        InsnCategory::Compute => self.step_compute(ctx, insn.kind, &decoded)?,
        InsnCategory::Load => self.step_load(ctx, insn.kind, &decoded)?,
        InsnCategory::Store => self.step_store(ctx, insn.kind, &decoded)?,
        InsnCategory::System => self.step_system(ctx, insn.kind, &decoded)?,
        InsnCategory::Invalid => ctx.trap(TrapCause::IllegalInstruction(word))?,
    } {
        ctx.on_normal_end(&insn, &decoded);
    };

    Ok(())
}
```

On the face of it, `step` has all the necessary complications to support self-modifying code.  If it doesn't actually support it, then that's because somewhere else they piled on some further complications on top that prevent it; instead of a simpler design like SP1's that avoids the possibility in the first place.

(As an extra bonus, they have about half a dozen places there where they need to deal with potentially invalid instructions.)

Before I close out, two more 'interesting' design choices of Risc0.

First, Risc0 commits to a hash digest of the ELF for their proofs, not something like our `InsnRecord` or SP1's `Instruction`.  That means they need to proof their decoding.  (Both Ceno and SP1 avoid that.) Please have a look at their `risc0_zkvm::compute_image_id`, if you want to verify that.

```rust
/// Compute and return the ImageID of the specified ELF binary.
#[cfg(not(target_os = "zkvm"))]
pub fn compute_image_id(elf: &[u8]) -> anyhow::Result<risc0_zkp::core::digest::Digest> {
    use risc0_zkvm_platform::{memory::GUEST_MAX_MEM, PAGE_SIZE};

    let program = Program::load_elf(elf, GUEST_MAX_MEM as u32)?;
    let image = MemoryImage::new(&program, PAGE_SIZE as u32)?;
    Ok(image.compute_id())
}
```

Second, here's the type of `Program::load_elf` used above:

```rust
pub fn load_elf(input: &[u8], max_mem: u32) -> Result<Program>`
```

And here's the definition of `Program`:

```rust
/// A RISC Zero program
pub struct Program {
    /// The entrypoint of the program
    pub entry: u32,

    /// The initial memory image
    pub image: BTreeMap<u32, u32>,
}
```

Their `Program` forgets all about the different sections of the ELF.  Which ones are supposed to be read-only, which one are supposed to be (non-) executable, etc.  I don't know for sure whether their prover supports self-modifying code, but it certainly supports jumping into data sections.  They have no way to prevent that. (To spell out the consequences: a sufficiently underhanded guest program author can bury some malicious code in the constants of the program, and then arrange for some other vulnerable part of the program to jump into that code.  An audit of the (Rust) source code of the guest won't reveal the malicious code, at most it reveals the [stack smashing](http://www.phrack.org/issues/49/14.html#article) vulnerability, but almost any piece of unsafe Rust code could hide that.  

Alternatively, carelessness can look like underhandedness. Thus, a clever attacker could find an existing program that might already spell out malicious code in its data section completely by accident.)

Enough background for now.  I'll reply to your specific points in a second comment later.
