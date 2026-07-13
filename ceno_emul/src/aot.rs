use crate::{
    EmuContext, InsnKind, Instruction, PC_STEP_SIZE, Program, Tracer, VMState, addr::ByteAddr,
    rv32im::TrapCause,
};
use anyhow::{Context, Result, anyhow, bail};
use libloading::{Library, Symbol};
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    os::raw::c_void,
    path::Path,
    process::Command,
    sync::Arc,
    time::{Duration, Instant},
};

type NativeEntry = unsafe extern "C" fn(*mut c_void, AotInsnFn, u64, *mut u64, u32) -> u32;
type AotInsnFn = unsafe extern "C" fn(*mut c_void, u32, *mut u32) -> u32;

const AOT_STATUS_HALTED: u32 = 0;
const AOT_STATUS_CONTINUE: u32 = 1;
const AOT_STATUS_ERROR: u32 = 2;

thread_local! {
    static LAST_AOT_ERROR: RefCell<Option<anyhow::Error>> = const { RefCell::new(None) };
}

#[derive(Debug)]
pub struct AotCompileReport {
    pub block_count: usize,
    pub reachable_instruction_count: usize,
    pub compile_load_time: Duration,
}

pub struct AotProgram {
    program: Arc<Program>,
    blocks: Vec<BasicBlock>,
    _library: Library,
    entry: NativeEntry,
    compile_load_time: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicBlock {
    pub start_pc: u32,
    pub end_pc: u32,
}

impl AotProgram {
    pub fn compile(program: Arc<Program>) -> Result<Self> {
        let started = Instant::now();
        let blocks = partition_basic_blocks(&program)?;
        let (library, entry) = compile_and_load_native(&program, &blocks)?;
        Ok(Self {
            program,
            blocks,
            _library: library,
            entry,
            compile_load_time: started.elapsed(),
        })
    }

    pub fn report(&self) -> AotCompileReport {
        AotCompileReport {
            block_count: self.blocks.len(),
            reachable_instruction_count: self
                .blocks
                .iter()
                .map(|block| ((block.end_pc - block.start_pc) / PC_STEP_SIZE as u32) as usize)
                .sum(),
            compile_load_time: self.compile_load_time,
        }
    }

    pub fn run_to_halt<T: Tracer>(
        &self,
        vm: &mut VMState<T>,
        max_steps: usize,
    ) -> Result<AotRunReport> {
        if !std::ptr::eq(vm.program(), self.program.as_ref()) {
            bail!("AOT program does not match VM program");
        }

        let started = Instant::now();
        LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = None);
        let mut executed_steps = 0u64;
        let native_status = unsafe {
            (self.entry)(
                vm as *mut VMState<T> as *mut c_void,
                aot_exec_one::<T>,
                max_steps as u64,
                &mut executed_steps,
                vm.get_pc().0,
            )
        };
        if native_status == AOT_STATUS_ERROR {
            let err = LAST_AOT_ERROR
                .with(|slot| slot.borrow_mut().take())
                .unwrap_or_else(|| anyhow!("AOT native step failed without error detail"));
            return Err(err);
        }
        if native_status != AOT_STATUS_HALTED {
            bail!("AOT native entry returned invalid status {native_status}");
        }
        Ok(AotRunReport {
            executed_steps: executed_steps as usize,
            execute_time: started.elapsed(),
        })
    }
}

#[derive(Debug)]
pub struct AotRunReport {
    pub executed_steps: usize,
    pub execute_time: Duration,
}

pub fn partition_basic_blocks(program: &Program) -> Result<Vec<BasicBlock>> {
    if program.instructions.is_empty() {
        bail!("AOT program has no instructions");
    }

    let mut leaders = BTreeSet::new();
    leaders.insert(program.entry);
    for (idx, &insn) in program.instructions.iter().enumerate() {
        let pc = program.base_address + (idx as u32 * PC_STEP_SIZE as u32);
        match insn.kind {
            InsnKind::BEQ
            | InsnKind::BNE
            | InsnKind::BLT
            | InsnKind::BGE
            | InsnKind::BLTU
            | InsnKind::BGEU => {
                leaders.insert(branch_target(pc, insn)?);
                if let Some(next_pc) = fallthrough_pc(program, pc) {
                    leaders.insert(next_pc);
                }
            }
            InsnKind::JAL => {
                leaders.insert(branch_target(pc, insn)?);
                if let Some(next_pc) = fallthrough_pc(program, pc) {
                    leaders.insert(next_pc);
                }
            }
            InsnKind::JALR | InsnKind::ECALL | InsnKind::INVALID => {
                if let Some(next_pc) = fallthrough_pc(program, pc) {
                    leaders.insert(next_pc);
                }
            }
            _ => {}
        }
    }

    let valid_leaders = leaders
        .into_iter()
        .filter(|pc| instruction_at(program, *pc).is_ok())
        .collect::<BTreeSet<_>>();

    let mut blocks = Vec::new();
    for &start_pc in &valid_leaders {
        let mut end_pc = start_pc;
        loop {
            let insn = instruction_at(program, end_pc)?;
            end_pc = end_pc.wrapping_add(PC_STEP_SIZE as u32);
            let terminates = terminates_block(insn.kind);
            if terminates
                || instruction_at(program, end_pc).is_err()
                || valid_leaders.contains(&end_pc)
            {
                blocks.push(BasicBlock { start_pc, end_pc });
                break;
            }
        }
    }

    Ok(blocks)
}

fn terminates_block(kind: InsnKind) -> bool {
    matches!(
        kind,
        InsnKind::BEQ
            | InsnKind::BNE
            | InsnKind::BLT
            | InsnKind::BGE
            | InsnKind::BLTU
            | InsnKind::BGEU
            | InsnKind::JAL
            | InsnKind::JALR
            | InsnKind::ECALL
            | InsnKind::INVALID
    )
}

fn instruction_at(program: &Program, pc: u32) -> Result<Instruction> {
    if !pc.is_multiple_of(PC_STEP_SIZE as u32) {
        bail!("instruction pc {pc:#010x} is misaligned");
    }
    let relative_pc = pc.wrapping_sub(program.base_address);
    let idx = (relative_pc / PC_STEP_SIZE as u32) as usize;
    program
        .instructions
        .get(idx)
        .copied()
        .ok_or_else(|| anyhow!("instruction pc {pc:#010x} is outside program"))
}

fn branch_target(pc: u32, insn: Instruction) -> Result<u32> {
    let target = ByteAddr(pc).wrapping_add(insn.imm as u32).0;
    if !target.is_multiple_of(PC_STEP_SIZE as u32) {
        bail!("branch target {target:#010x} is misaligned");
    }
    Ok(target)
}

fn fallthrough_pc(program: &Program, pc: u32) -> Option<u32> {
    let next_pc = pc.wrapping_add(PC_STEP_SIZE as u32);
    let relative_pc = next_pc.wrapping_sub(program.base_address);
    let idx = (relative_pc / PC_STEP_SIZE as u32) as usize;
    (idx < program.instructions.len()).then_some(next_pc)
}

fn compile_and_load_native(
    program: &Program,
    blocks: &[BasicBlock],
) -> Result<(Library, NativeEntry)> {
    let dir = tempfile::Builder::new()
        .prefix("ceno-aot-")
        .tempdir()
        .context("create AOT tempdir")?;
    let asm_path = dir.path().join("program.S");
    let so_path = dir.path().join("program.so");
    write_assembly(&asm_path, program, blocks)?;
    let output = Command::new("cc")
        .arg("-shared")
        .arg("-fPIC")
        .arg("-x")
        .arg("assembler")
        .arg(&asm_path)
        .arg("-o")
        .arg(&so_path)
        .output()
        .context("invoke cc for AOT assembly")?;
    if !output.status.success() {
        bail!(
            "AOT assembly compile failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let library = unsafe { Library::new(&so_path) }.context("load AOT shared object")?;
    let entry = unsafe {
        let symbol: Symbol<'_, NativeEntry> = library
            .get(b"ceno_aot_entry")
            .context("load ceno_aot_entry")?;
        *symbol
    };
    Ok((library, entry))
}

fn write_assembly(path: &Path, program: &Program, blocks: &[BasicBlock]) -> Result<()> {
    let mut labels = BTreeMap::new();
    for (idx, block) in blocks.iter().enumerate() {
        labels.insert(block.start_pc, format!("L_bb_{idx}"));
    }

    let mut file = fs::File::create(path).context("create AOT assembly")?;
    writeln!(file, ".text")?;
    writeln!(file, ".globl ceno_aot_entry")?;
    writeln!(file, ".type ceno_aot_entry, @function")?;
    writeln!(file, "ceno_aot_entry:")?;
    writeln!(file, "    pushq %rbx")?;
    writeln!(file, "    pushq %r12")?;
    writeln!(file, "    pushq %r13")?;
    writeln!(file, "    pushq %r14")?;
    writeln!(file, "    pushq %r15")?;
    writeln!(file, "    subq $16, %rsp")?;
    writeln!(file, "    movq %rdi, %r12")?;
    writeln!(file, "    movq %rsi, %r13")?;
    writeln!(file, "    movq %rdx, %r14")?;
    writeln!(file, "    movq %rcx, %rbx")?;
    writeln!(file, "    movl %r8d, %r15d")?;
    writeln!(file, "    movq $0, 0(%rsp)")?;
    writeln!(file, "    movl %r15d, 8(%rsp)")?;
    writeln!(file, "L_dispatch:")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    cmpq %r14, %rax")?;
    writeln!(file, "    jae L_done")?;
    for block in blocks {
        let label = labels.get(&block.start_pc).expect("block label must exist");
        writeln!(file, "    cmpl ${:#010x}, %r15d", block.start_pc)?;
        writeln!(file, "    je {label}")?;
    }
    writeln!(file, "    jmp L_dynamic")?;
    for block in blocks {
        let label = labels.get(&block.start_pc).expect("block label must exist");
        writeln!(file, "{label}:")?;
        let mut pc = block.start_pc;
        while pc < block.end_pc {
            emit_call_one(&mut file, pc)?;
            let insn = instruction_at(program, pc)?;
            pc = pc.wrapping_add(PC_STEP_SIZE as u32);
            if terminates_block(insn.kind) {
                writeln!(file, "    jmp L_dispatch")?;
            }
        }
        writeln!(file, "    jmp L_dispatch")?;
    }
    writeln!(file, "L_dynamic:")?;
    emit_call_current_pc(&mut file)?;
    writeln!(file, "    jmp L_dispatch")?;
    writeln!(file, "L_done:")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    movq %rax, (%rbx)")?;
    writeln!(file, "    movl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    jmp L_return")?;
    writeln!(file, "L_error:")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    movq %rax, (%rbx)")?;
    writeln!(file, "    movl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "L_return:")?;
    writeln!(file, "    addq $16, %rsp")?;
    writeln!(file, "    popq %r15")?;
    writeln!(file, "    popq %r14")?;
    writeln!(file, "    popq %r13")?;
    writeln!(file, "    popq %r12")?;
    writeln!(file, "    popq %rbx")?;
    writeln!(file, "    ret")?;
    writeln!(file, ".section .note.GNU-stack,\"\",@progbits")?;
    Ok(())
}

fn emit_call_one(mut file: impl Write, pc: u32) -> Result<()> {
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl ${pc:#010x}, %esi")?;
    writeln!(file, "    call *%r13")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "    incq 0(%rsp)")?;
    writeln!(file, "    movl 8(%rsp), %r15d")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je L_done")?;
    writeln!(file, "    movq 0(%rsp), %rax")?;
    writeln!(file, "    cmpq %r14, %rax")?;
    writeln!(file, "    jae L_done")?;
    Ok(())
}

fn emit_call_current_pc(mut file: impl Write) -> Result<()> {
    writeln!(file, "    leaq 8(%rsp), %rdx")?;
    writeln!(file, "    movq %r12, %rdi")?;
    writeln!(file, "    movl %r15d, %esi")?;
    writeln!(file, "    call *%r13")?;
    writeln!(file, "    cmpl ${AOT_STATUS_ERROR}, %eax")?;
    writeln!(file, "    je L_error")?;
    writeln!(file, "    incq 0(%rsp)")?;
    writeln!(file, "    movl 8(%rsp), %r15d")?;
    writeln!(file, "    cmpl ${AOT_STATUS_HALTED}, %eax")?;
    writeln!(file, "    je L_done")?;
    Ok(())
}

unsafe extern "C" fn aot_exec_one<T: Tracer>(vm: *mut c_void, pc: u32, next_pc: *mut u32) -> u32 {
    let vm = unsafe { &mut *(vm as *mut VMState<T>) };
    if vm.halted() {
        unsafe {
            *next_pc = vm.get_pc().0;
        }
        return AOT_STATUS_HALTED;
    }

    let pc = ByteAddr(pc);
    vm.set_pc(pc);
    let result = (|| -> Result<()> {
        let Some(insn) = vm.fetch(pc.waddr()) else {
            vm.trap(TrapCause::InstructionAccessFault)?;
            bail!(
                "Fatal: could not fetch instruction at pc={pc:?}, ELF does not have instructions there."
            );
        };
        crate::rv32im::step_fetched(vm, &insn)?;
        let step = vm.tracer_mut().advance();
        if vm.tracer().is_busy_loop(&step) && !vm.halted() {
            bail!("Stuck in loop {}", "{}");
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            unsafe {
                *next_pc = vm.get_pc().0;
            }
            if vm.halted() {
                AOT_STATUS_HALTED
            } else {
                AOT_STATUS_CONTINUE
            }
        }
        Err(err) => {
            unsafe {
                *next_pc = vm.get_pc().0;
            }
            LAST_AOT_ERROR.with(|slot| *slot.borrow_mut() = Some(err));
            AOT_STATUS_ERROR
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CENO_PLATFORM, EmuContext, encode_rv32};
    use std::sync::Arc;

    fn program(instructions: Vec<Instruction>) -> Program {
        Program::new(
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.pc_base(),
            CENO_PLATFORM.heap.start,
            instructions,
            Default::default(),
        )
    }

    #[test]
    fn partitions_direct_branch_and_fallthrough() {
        let base = CENO_PLATFORM.pc_base();
        let program = program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, 8),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 2),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]);

        let blocks = partition_basic_blocks(&program).unwrap();
        assert_eq!(
            blocks,
            vec![
                BasicBlock {
                    start_pc: base,
                    end_pc: base + 8,
                },
                BasicBlock {
                    start_pc: base + 8,
                    end_pc: base + 12,
                },
                BasicBlock {
                    start_pc: base + 12,
                    end_pc: base + 16,
                },
            ]
        );
    }

    #[test]
    fn invalid_instruction_errors_if_executed() {
        let program = Arc::new(program(vec![encode_rv32(InsnKind::INVALID, 0, 0, 0, 0)]));
        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut vm = VMState::new(CENO_PLATFORM.clone(), program);
        let err = aot.run_to_halt(&mut vm, 1).unwrap_err().to_string();
        assert!(err.contains("IllegalInstruction"));
    }

    #[test]
    fn aot_trace_matches_interpreter_for_supported_loop() {
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 5),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 0),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::ADD, 2, 1, 2, 0),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -8),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        let report = aot.run_to_halt(&mut aot_vm, 100).unwrap();

        assert_eq!(report.executed_steps, interp.tracer().executed_insts());
        assert_eq!(aot_vm.peek_register(1), interp.peek_register(1));
        assert_eq!(aot_vm.peek_register(2), interp.peek_register(2));
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }

    #[test]
    fn aot_respects_max_steps_without_halting() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::ADDI, 0, 0, 1, 3),
            encode_rv32(InsnKind::ADDI, 1, 0, 1, -1),
            encode_rv32(InsnKind::BNE, 1, 0, 0, -4),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));
        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut vm = VMState::new(CENO_PLATFORM.clone(), program);

        let report = aot.run_to_halt(&mut vm, 2).unwrap();

        assert_eq!(report.executed_steps, 2);
        assert!(!vm.halted());
        assert_eq!(vm.get_pc().0, base + 8);

        let report = aot.run_to_halt(&mut vm, 10).unwrap();
        assert_eq!(report.executed_steps, 6);
        assert!(vm.halted());
    }

    #[test]
    fn aot_dynamic_dispatch_handles_jalr_into_block_middle() {
        let base = CENO_PLATFORM.pc_base();
        let program = Arc::new(program(vec![
            encode_rv32(InsnKind::JALR, 1, 0, 0, 0),
            encode_rv32(InsnKind::ADDI, 0, 0, 3, 1),
            encode_rv32(InsnKind::ADDI, 0, 0, 2, 7),
            encode_rv32(InsnKind::ECALL, 0, 0, 0, 0),
        ]));

        let mut interp = VMState::new(CENO_PLATFORM.clone(), program.clone());
        interp.init_register_unsafe(1, base + 8);
        while interp.next_step_record().unwrap().is_some() {}

        let aot = AotProgram::compile(program.clone()).unwrap();
        let mut aot_vm = VMState::new(CENO_PLATFORM.clone(), program);
        aot_vm.init_register_unsafe(1, base + 8);
        let report = aot.run_to_halt(&mut aot_vm, 10).unwrap();

        assert_eq!(report.executed_steps, 3);
        assert_eq!(aot_vm.peek_register(2), 7);
        assert_eq!(aot_vm.peek_register(3), 0);
        assert_eq!(
            aot_vm.tracer().recorded_steps(),
            interp.tracer().recorded_steps()
        );
    }
}
