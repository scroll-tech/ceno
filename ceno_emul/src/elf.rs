// Based on: https://github.com/risc0/risc0/blob/6b6daeafa1545984aa28581fca56d9ef13dcbae6/risc0/binfmt/src/elf.rs
//
// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate alloc;

use std::iter::successors;

use alloc::collections::BTreeMap;
use itertools::Itertools;

use crate::{CENO_PLATFORM, addr::WORD_SIZE, disassemble::transpile, rv32im::Instruction};
use anyhow::{Context, Result, anyhow, bail};
use elf::{
    ElfBytes,
    abi::{PF_R, PF_W, PF_X},
    endian::LittleEndian,
    file::Class,
};

/// A RISC Zero program
#[derive(Clone, Debug)]
pub struct Program {
    /// The entrypoint of the program
    pub entry: u32,
    /// This is the lowest address of the program's executable code
    pub base_address: u32,
    /// This is the heap start address, match with _sheap retrieve from elf
    pub sheap: u32,
    /// The instructions of the program
    pub instructions: Vec<Instruction>,
    /// The initial memory image
    pub image: BTreeMap<u32, u32>,
    /// Workload-independent AOT roots encoded by LLVM in `.llvm_bb_addr_map`.
    pub static_aot_roots: Option<Vec<u32>>,
}

impl From<&[Instruction]> for Program {
    fn from(insn_codes: &[Instruction]) -> Program {
        Self {
            entry: CENO_PLATFORM.pc_base(),
            base_address: CENO_PLATFORM.pc_base(),
            sheap: CENO_PLATFORM.heap.start,
            instructions: insn_codes.to_vec(),
            image: Default::default(),
            static_aot_roots: None,
        }
    }
}

impl Program {
    /// Create program
    pub fn new(
        entry: u32,
        base_address: u32,
        sheap: u32,
        instructions: Vec<Instruction>,
        image: BTreeMap<u32, u32>,
    ) -> Program {
        Self {
            entry,
            base_address,
            sheap,
            instructions,
            image,
            static_aot_roots: None,
        }
    }

    /// Initialize a RISC Zero Program from an appropriate ELF file
    pub fn load_elf(input: &[u8], max_mem: u32) -> Result<Program> {
        let mut instructions: Vec<u32> = Vec::new();
        let mut image: BTreeMap<u32, u32> = BTreeMap::new();
        let mut base_address = None;

        let elf = ElfBytes::<LittleEndian>::minimal_parse(input)
            .map_err(|err| anyhow!("Elf parse error: {err}"))?;
        if elf.ehdr.class != Class::ELF32 {
            bail!("Not a 32-bit ELF");
        }
        if elf.ehdr.e_machine != elf::abi::EM_RISCV {
            bail!("Invalid machine type, must be RISC-V");
        }
        if elf.ehdr.e_type != elf::abi::ET_EXEC {
            bail!("Invalid ELF type, must be executable");
        }
        let entry: u32 = elf
            .ehdr
            .e_entry
            .try_into()
            .map_err(|err| anyhow!("e_entry was larger than 32 bits. {err}"))?;
        if entry >= max_mem || !entry.is_multiple_of(WORD_SIZE as u32) {
            bail!("Invalid entrypoint");
        }
        let segments = elf.segments().ok_or(anyhow!("Missing segment table"))?;
        if segments.len() > 256 {
            bail!("Too many program headers");
        }
        let symbols = collect_addr_symbols_mapping(&elf)?;
        for (idx, segment) in segments
            .iter()
            .filter(|x| x.p_type == elf::abi::PT_LOAD)
            .enumerate()
        {
            let file_size: u32 = segment
                .p_filesz
                .try_into()
                .map_err(|err| anyhow!("filesize was larger than 32 bits. {err}"))?;
            if file_size >= max_mem {
                bail!("Invalid segment file_size");
            }
            let mem_size: u32 = segment
                .p_memsz
                .try_into()
                .map_err(|err| anyhow!("mem_size was larger than 32 bits {err}"))?;
            if mem_size >= max_mem {
                bail!("Invalid segment mem_size");
            }
            let vaddr: u32 = segment
                .p_vaddr
                .try_into()
                .map_err(|err| anyhow!("vaddr is larger than 32 bits. {err}"))?;
            let p_flags = segment.p_flags;
            if (p_flags & PF_X) != 0 {
                if base_address.is_none() {
                    base_address = Some(vaddr);
                } else {
                    return Err(anyhow!("only support one executable segment"));
                }
            }
            if !vaddr.is_multiple_of(WORD_SIZE as u32) {
                bail!("vaddr {vaddr:08x} is unaligned");
            }
            tracing::debug!(
                "ELF segment {idx}: {}{}{} vaddr=0x{vaddr:08x} file_size={file_size} mem_size={mem_size}",
                if p_flags & PF_R != 0 { "R" } else { "-" },
                if p_flags & PF_W != 0 { "W" } else { "-" },
                if p_flags & PF_X != 0 { "X" } else { "-" },
            );
            let offset: u32 = segment
                .p_offset
                .try_into()
                .map_err(|err| anyhow!("offset is larger than 32 bits. {err}"))?;

            // process initialized data
            (0..file_size).step_by(WORD_SIZE).try_for_each(|i| {
                let addr = vaddr.checked_add(i).context("Invalid segment vaddr")?;
                if addr >= max_mem {
                    bail!("Address [0x{addr:x}] exceeds max [0x{max_mem:x}]");
                }

                let word = (0..WORD_SIZE as u32)
                    .take((file_size - i) as usize)
                    .enumerate()
                    .fold(0u32, |acc, (j, _)| {
                        let offset = (offset + i + j as u32) as usize;
                        let byte = *input.get(offset).unwrap_or(&0);
                        acc | ((byte as u32) << (j * 8))
                    });

                image.insert(addr, word);
                if (segment.p_flags & PF_X) != 0 {
                    instructions.push(word);
                }

                Ok(())
            })?;

            // only pad uninitialized region if a symbol exists in the range
            if let Some((max_addr, _)) = find_max_symbol_in_range(
                &symbols,
                vaddr as u64,
                vaddr.checked_add(mem_size).context("Invalid mem_size")? as u64,
            ) {
                let zero_upper = (*max_addr as u32).saturating_sub(vaddr);
                (file_size..=zero_upper)
                    .step_by(WORD_SIZE)
                    .try_for_each(|i| {
                        let addr = vaddr.checked_add(i).context("Invalid segment vaddr")?;
                        if addr >= max_mem {
                            bail!("zero-fill addr [0x{addr:x}] exceeds max [0x{max_mem:x}]");
                        }
                        image.insert(addr, 0);
                        Ok(())
                    })?;
            }
        }

        if base_address.is_none() {
            return Err(anyhow!("does not have executable segment"));
        }
        let base_address = base_address.unwrap();
        assert!(entry >= base_address);
        assert!((entry - base_address) as usize <= instructions.len() * WORD_SIZE);

        let instructions = transpile(base_address, &instructions);
        let text_end = base_address
            .checked_add((instructions.len() * WORD_SIZE) as u32)
            .context("executable text range overflow")?;
        let static_aot_roots = elf
            .section_header_by_name(".llvm_bb_addr_map")?
            .map(|section| {
                let (data, _) = elf.section_data(&section)?;
                parse_llvm_bb_addr_map_v3(data, base_address, text_end)
            })
            .transpose()?;

        // program data include text/rodata/data/bss
        // truncate padding 0 section after bss
        let mut program_data = image
            .into_iter()
            .sorted_by_key(|(addr, _)| *addr)
            .collect_vec();

        // record current max address of bss
        // as later when we do static program data padding, it must cover max bss section and assure it's well constrained
        let bss_max_addr = program_data.last().cloned();

        // padding program_data to next power of 2 from last addr
        let padding_size = program_data.len().next_power_of_two() - program_data.len();
        if padding_size > 0 {
            program_data.extend(
                successors(
                    program_data.last().map(|d| (d.0 + WORD_SIZE as u32, 0)),
                    |(prev_addr, _)| Some((prev_addr + WORD_SIZE as u32, 0)),
                )
                .take(padding_size)
                .collect_vec(),
            );
        }

        let Some(((padded_max_static_addr, _), (bss_max_addr, _))) =
            program_data.last().zip(bss_max_addr)
        else {
            return Err(anyhow!("invalid size of data"));
        };

        if *padded_max_static_addr < bss_max_addr {
            return Err(anyhow!(
                "padded_max_static_addr should larger than bss_max_addr"
            ));
        }

        // retrieve _sheap from elf
        let sheap = symbols
            .iter()
            .find(|(_, v)| *v == "_sheap")
            .map(|(k, _)| *k)
            .ok_or_else(|| anyhow!("unable to find _sheap symbol"))? as u32;

        // there should be no
        if *padded_max_static_addr >= sheap {
            return Err(anyhow!(
                "padded_max_static_addr overlap with _sheap heap start address"
            ));
        }

        Ok(Program {
            entry,
            base_address,
            sheap,
            image: program_data.into_iter().collect::<BTreeMap<u32, u32>>(),
            instructions,
            static_aot_roots,
        })
    }
}

const LLVM_BB_ADDR_MAP_VERSION: u8 = 3;
const LLVM_BB_ADDR_MAP_CALLSITE_END_OFFSETS: u8 = 1 << 5;
const LLVM_BB_METADATA_MASK: u32 = 0x1f;

fn parse_llvm_bb_addr_map_v3(data: &[u8], text_start: u32, text_end: u32) -> Result<Vec<u32>> {
    if data.is_empty() {
        bail!("LLVM basic-block address map is empty");
    }
    let mut cursor = 0usize;
    let mut roots = Vec::new();
    while cursor < data.len() {
        let version = read_u8(data, &mut cursor, "version")?;
        if version != LLVM_BB_ADDR_MAP_VERSION {
            bail!("unsupported LLVM basic-block address map version {version}");
        }
        let features = read_u8(data, &mut cursor, "features")?;
        if features & !LLVM_BB_ADDR_MAP_CALLSITE_END_OFFSETS != 0 {
            bail!("unsupported LLVM basic-block address map features {features:#04x}");
        }
        let function_address = read_u32(data, &mut cursor, "function address")?;
        let block_count = read_uleb_u32(data, &mut cursor, "block count")?;
        let mut previous_block_end = 0u32;
        for _ in 0..block_count {
            let _id = read_uleb_u32(data, &mut cursor, "block id")?;
            let offset_delta = read_uleb_u32(data, &mut cursor, "block offset")?;
            let block_offset = previous_block_end
                .checked_add(offset_delta)
                .context("LLVM basic-block offset overflow")?;
            let block_pc = function_address
                .checked_add(block_offset)
                .context("LLVM basic-block address overflow")?;

            let mut callsite_offsets = Vec::new();
            let mut last_callsite_offset = 0u32;
            if features & LLVM_BB_ADDR_MAP_CALLSITE_END_OFFSETS != 0 {
                let callsite_count = read_uleb_u32(data, &mut cursor, "callsite count")?;
                for _ in 0..callsite_count {
                    last_callsite_offset = last_callsite_offset
                        .checked_add(read_uleb_u32(data, &mut cursor, "callsite offset")?)
                        .context("LLVM callsite offset overflow")?;
                    callsite_offsets.push(last_callsite_offset);
                }
            }
            let block_size = last_callsite_offset
                .checked_add(read_uleb_u32(data, &mut cursor, "block size")?)
                .context("LLVM basic-block size overflow")?;
            let metadata = read_uleb_u32(data, &mut cursor, "block metadata")?;
            if metadata & !LLVM_BB_METADATA_MASK != 0 {
                bail!("invalid LLVM basic-block metadata {metadata:#x}");
            }
            validate_text_pc(block_pc, text_start, text_end, "basic-block")?;
            roots.push(block_pc);
            for offset in callsite_offsets {
                if offset > block_size {
                    bail!("LLVM callsite end offset lies outside its basic block");
                }
                let return_pc = block_pc
                    .checked_add(offset)
                    .context("LLVM callsite return address overflow")?;
                validate_text_pc(return_pc, text_start, text_end, "callsite return")?;
                roots.push(return_pc);
            }
            previous_block_end = block_offset
                .checked_add(block_size)
                .context("LLVM basic-block end overflow")?;
            let block_end = function_address
                .checked_add(previous_block_end)
                .context("LLVM basic-block end address overflow")?;
            if block_end > text_end {
                bail!("LLVM basic-block end {block_end:#010x} lies outside executable text");
            }
        }
    }
    roots.sort_unstable();
    roots.dedup();
    Ok(roots)
}

fn validate_text_pc(pc: u32, text_start: u32, text_end: u32, kind: &str) -> Result<()> {
    if pc < text_start || pc >= text_end || !pc.is_multiple_of(WORD_SIZE as u32) {
        bail!("LLVM {kind} PC {pc:#010x} lies outside or is unaligned in executable text");
    }
    Ok(())
}

fn read_u8(data: &[u8], cursor: &mut usize, field: &str) -> Result<u8> {
    let value = data
        .get(*cursor)
        .copied()
        .with_context(|| format!("truncated LLVM basic-block address map {field}"))?;
    *cursor += 1;
    Ok(value)
}

fn read_u32(data: &[u8], cursor: &mut usize, field: &str) -> Result<u32> {
    let end = cursor
        .checked_add(4)
        .context("LLVM basic-block address map cursor overflow")?;
    let bytes: [u8; 4] = data
        .get(*cursor..end)
        .with_context(|| format!("truncated LLVM basic-block address map {field}"))?
        .try_into()
        .expect("four-byte slice");
    *cursor = end;
    Ok(u32::from_le_bytes(bytes))
}

fn read_uleb_u32(data: &[u8], cursor: &mut usize, field: &str) -> Result<u32> {
    let mut value = 0u32;
    for shift in (0..=28).step_by(7) {
        let byte = read_u8(data, cursor, field)?;
        let payload = u32::from(byte & 0x7f);
        if shift == 28 && payload > 0x0f {
            bail!("LLVM basic-block address map {field} ULEB128 overflows u32");
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("LLVM basic-block address map {field} ULEB128 overflows u32")
}

fn collect_addr_symbols_mapping<'data>(
    elf: &ElfBytes<'data, LittleEndian>,
) -> Result<BTreeMap<u64, String>> {
    let mut symbols = BTreeMap::new();

    if let Some((symtab, strtab)) = elf.symbol_table()? {
        for symbol in symtab.iter() {
            if let Ok(name) = strtab.get(symbol.st_name as usize)
                && !name.is_empty()
                && symbol.st_value != 0
            {
                symbols.insert(symbol.st_value, name.to_string());
            }
        }
    }

    Ok(symbols)
}

fn find_max_symbol_in_range(
    symbols: &BTreeMap<u64, String>,
    start: u64,
    end: u64,
) -> Option<(&u64, &String)> {
    symbols.range(start..end).max_by_key(|&(addr, _)| addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uleb(mut value: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                return bytes;
            }
        }
    }

    fn header(base: u32, features: u8, blocks: u32) -> Vec<u8> {
        let mut bytes = vec![LLVM_BB_ADDR_MAP_VERSION, features];
        bytes.extend_from_slice(&base.to_le_bytes());
        bytes.extend(uleb(blocks));
        bytes
    }

    #[test]
    fn parses_v3_delta_offsets_and_multiple_functions() {
        let mut map = header(0x1000, 0, 2);
        map.extend([0, 0, 8, 8]);
        map.extend([1, 4, 4, 0]);
        map.extend(header(0x1020, 0, 1));
        map.extend([0, 0, 4, 0]);

        assert_eq!(
            parse_llvm_bb_addr_map_v3(&map, 0x1000, 0x1040).unwrap(),
            vec![0x1000, 0x100c, 0x1020]
        );
    }

    #[test]
    fn parses_callsite_end_offsets_as_return_pcs() {
        let mut map = header(0x1000, LLVM_BB_ADDR_MAP_CALLSITE_END_OFFSETS, 1);
        map.extend([0, 0, 2, 4, 8, 4, 0]);

        assert_eq!(
            parse_llvm_bb_addr_map_v3(&map, 0x1000, 0x1020).unwrap(),
            vec![0x1000, 0x1004, 0x100c]
        );
    }

    #[test]
    fn accepts_zero_sized_machine_blocks() {
        let mut map = header(0x1000, 0, 2);
        map.extend([0, 0, 0, 0]);
        map.extend([1, 4, 4, 0]);

        assert_eq!(
            parse_llvm_bb_addr_map_v3(&map, 0x1000, 0x1020).unwrap(),
            vec![0x1000, 0x1004]
        );
    }

    #[test]
    fn rejects_truncated_uleb128() {
        let mut map = header(0x1000, 0, 1);
        map.push(0x80);
        let err = parse_llvm_bb_addr_map_v3(&map, 0x1000, 0x1020)
            .unwrap_err()
            .to_string();
        assert!(err.contains("truncated"), "{err}");
    }

    #[test]
    fn rejects_uleb128_overflow() {
        let mut map = header(0x1000, 0, 1);
        map.extend([0x80, 0x80, 0x80, 0x80, 0x10]);
        let err = parse_llvm_bb_addr_map_v3(&map, 0x1000, 0x1020)
            .unwrap_err()
            .to_string();
        assert!(err.contains("overflows u32"), "{err}");
    }

    #[test]
    fn rejects_unsupported_version_and_features() {
        let mut version = header(0x1000, 0, 0);
        version[0] = 2;
        assert!(
            parse_llvm_bb_addr_map_v3(&version, 0x1000, 0x1020)
                .unwrap_err()
                .to_string()
                .contains("unsupported")
        );
        let features = header(0x1000, 1, 0);
        assert!(
            parse_llvm_bb_addr_map_v3(&features, 0x1000, 0x1020)
                .unwrap_err()
                .to_string()
                .contains("features")
        );
    }

    #[test]
    fn rejects_invalid_metadata_and_out_of_text_pcs() {
        let mut metadata = header(0x1000, 0, 1);
        metadata.extend([0, 0, 4, 0x20]);
        assert!(
            parse_llvm_bb_addr_map_v3(&metadata, 0x1000, 0x1020)
                .unwrap_err()
                .to_string()
                .contains("metadata")
        );

        let mut outside = header(0x1020, 0, 1);
        outside.extend([0, 0, 4, 0]);
        assert!(
            parse_llvm_bb_addr_map_v3(&outside, 0x1000, 0x1020)
                .unwrap_err()
                .to_string()
                .contains("outside")
        );
    }
}
