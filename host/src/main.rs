use ceno_emul::CENO_PLATFORM;
use ceno_host::CenoStdin;

// TODO(Matthias): much of this is copied from `test_elf.rs` in Ceno.  These are generally useful
// functions, so we should make them available for importing from the library, instead of copying
// them here.
//
// So in the end, this file should just have a really simple main.
// See how sproll-evm does it with SP1.

fn main() {
    let mut hints = CenoStdin::default();
    hints.write(&"This is my hint string.".to_string()).unwrap();
    hints.write(&1997_u32).unwrap();
    hints.write(&1999_u32).unwrap();

    let all_messages = ceno_host::run(CENO_PLATFORM, elf::ELF, &hints);

    for msg in &all_messages {
        print!("{msg}");
    }
}
