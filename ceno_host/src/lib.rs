// See `make_stdin` and `consume` for the main entry points, and how this would look
// for the host and guest respectively for the user of our library.
// Everything else in here would be hidden.

use itertools::izip;
use rkyv::{
    Serialize, api::high::HighSerializer, rancor::Error, ser::allocator::ArenaHandle, to_bytes,
    util::AlignedVec,
};

#[derive(Default)]
pub struct CenoStdin {
    pub items: Vec<AlignedVec>,
}

pub struct SerialisedCenoStdin(pub AlignedVec);

impl CenoStdin {
    pub fn write_slice(&mut self, bytes: AlignedVec) {
        self.items.push(bytes);
    }

    pub fn write(
        &mut self,
        item: &impl for<'a> Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, Error>>,
    ) -> Result<(), Error> {
        let bytes = to_bytes::<Error>(item)?;
        self.write_slice(bytes);
        Ok(())
    }

    pub fn finalise(&self) -> AlignedVec {
        // TODO: perhaps don't hardcode 16 here.
        // It's from rkyv's format, so we can probably take it from there somehow?
        // TODO: clean this up.
        let initial_offset = (size_of::<u32>() * self.items.len()).next_multiple_of(16);
        println!("offset: {}", initial_offset);
        let offsets: Vec<u32> = self
            .items
            .iter()
            .scan(initial_offset, |acc, bytes| {
                let output = (*acc + bytes.len()) as u32;
                print!("len: {}\t", bytes.len());
                *acc += bytes.len().next_multiple_of(16);
                println!("acc: {}", *acc);
                Some(output)
            })
            .collect();
        let offsets_u8: Vec<u8> = offsets.iter().copied().flat_map(u32::to_le_bytes).collect();
        let mut buf: AlignedVec = AlignedVec::new();
        buf.extend_from_slice(&offsets_u8);
        println!("buf.len() after offsets: {}", buf.len());
        buf.extend_from_slice(&vec![0; buf.len().next_multiple_of(16) - buf.len()]);
        println!("buf.len() after offset padding: {}", buf.len());
        for (offset, item) in izip!(offsets, &self.items) {
            buf.extend_from_slice(item);
            buf.extend_from_slice(&vec![0; buf.len().next_multiple_of(16) - buf.len()]);
            assert_eq!(buf.len(), offset.next_multiple_of(16) as usize);
        }
        buf
    }
}
