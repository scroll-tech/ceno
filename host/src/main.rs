use ceno_emul::CENO_PLATFORM;
use ceno_host::{CenoStdin, run};

fn main() {
    let mut hints = CenoStdin::default();
    hints.write(&"This is my hint string.".to_string()).unwrap();
    hints.write(&1997_u32).unwrap();
    hints.write(&1999_u32).unwrap();
    // hints.write(&true).unwrap();
    hints.write(&false).unwrap();

    let all_messages = run(CENO_PLATFORM, elf::ELF, &hints);

    for msg in &all_messages {
        print!("{msg}");
    }
}
