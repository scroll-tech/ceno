// See `make_stdin` and `consume` for the main entry points, and how this would look
// for the host and guest respectively for the user of our library.
// Everything else in here would be hidden.

use itertools::izip;
use rkyv::{
    Portable, Serialize,
    api::high::{HighSerializer, HighValidator},
    bytecheck::CheckBytes,
    rancor::Error,
    ser::allocator::ArenaHandle,
    to_bytes,
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

    pub fn finalise(&self) -> SerialisedCenoStdin {
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
        SerialisedCenoStdin(buf)
    }
}

pub struct SerialisedCenoStdinIter<'a> {
    buf: &'a SerialisedCenoStdin,
    next: usize,
}

impl<'b> SerialisedCenoStdinIter<'b> {
    pub fn read<'a, T>(&'a mut self) -> &'b T
    where
        T: Portable + for<'c> CheckBytes<HighValidator<'c, Error>>,
    {
        rkyv::access::<T, Error>(self.read_slice()).unwrap()
    }

    pub fn read_slice<'a>(&'a mut self) -> &'b [u8] {
        self.next().unwrap()
    }
}

impl<'a> Iterator for SerialisedCenoStdinIter<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let len = u32::from_le_bytes(
            self.buf.0[self.next..][..size_of::<u32>()]
                .try_into()
                .unwrap(),
        ) as usize;
        self.next += size_of::<u32>();
        Some(&self.buf.0[..len])
    }
}

impl<'a> IntoIterator for &'a SerialisedCenoStdin {
    type Item = &'a [u8];
    type IntoIter = SerialisedCenoStdinIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SerialisedCenoStdinIter { next: 0, buf: self }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rkyv::{
        Archive, Deserialize, deserialize,
        rancor::{Error, Failure},
        to_bytes,
        util::AlignedVec,
    };

    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(
        // This will generate a PartialEq impl between our unarchived
        // and archived types
        compare(PartialEq),
        // Derives can be passed through to the generated type:
        derive(Debug),
    )]
    struct Test {
        int: u32,
        string: String,
        option: Option<Vec<i32>>,
    }

    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    #[rkyv(
        // This will generate a PartialEq impl between our unarchived
        // and archived types
        compare(PartialEq),
        // Derives can be passed through to the generated type:
        derive(Debug),
    )]
    struct Toast {
        stuff: Option<Vec<String>>,
    }

    /// The equivalent of this function would run in the host.
    ///
    /// We create three different items, and show that we can read them back in `consume`.
    pub fn make_stdin() -> SerialisedCenoStdin {
        let mut stdin = CenoStdin::default();
        stdin
            .write(&Test {
                int: 0xDEAD_BEEF,
                string: "hello world".to_string(),
                option: Some(vec![1, 2, 3, 4]),
            })
            .unwrap();
        stdin.write(&0xaf_u8).unwrap();
        stdin
            .write(&Toast {
                stuff: Some(vec!["hello scroll".to_string()]),
            })
            .unwrap();
        stdin.finalise()
    }

    /// The equivalent of this function would run in the guest.
    ///
    /// `stdin` would be the memory mapped region for private hints.
    pub fn consume(stdin: SerialisedCenoStdin) {
        println!("\nConsuming...");
        let mut iter: SerialisedCenoStdinIter = stdin.into_iter();
        let test1: &ArchivedTest = iter.read();
        assert_eq!(test1, &Test {
            int: 0xDEAD_BEEF,
            string: "hello world".to_string(),
            option: Some(vec![1, 2, 3, 4]),
        });
        let number: &u8 = iter.read();
        assert_eq!(number, &0xaf_u8);
        let test2: &ArchivedToast = iter.read();
        assert_eq!(test2, &Toast {
            stuff: Some(vec!["hello scroll".to_string()]),
        });
    }

    #[test]
    fn test_prepare_and_consume_items() {
        let stdin = make_stdin();
        consume(stdin);
    }

    #[test]
    fn test_rkyv_padding() {
        let value = Test {
            int: 42,
            string: "hello world".to_string(),
            option: Some(vec![1, 2, 3, 4]),
        };

        // Serializing is as easy as a single function call
        let bytes: AlignedVec = to_bytes::<Error>(&value).unwrap();

        {
            // Or you can customize your serialization for better performance or control
            // over resource usage
            use rkyv::{api::high::to_bytes_with_alloc, ser::allocator::Arena};

            let mut arena = Arena::new();
            let _bytes = to_bytes_with_alloc::<_, Error>(&value, arena.acquire()).unwrap();
        }
        // You can use the safe API for fast zero-copy deserialization
        let archived = rkyv::access::<ArchivedTest, Failure>(&bytes[..]).unwrap();
        assert_eq!(archived, &value);

        // And you can always deserialize back to the original type
        let deserialized = deserialize::<Test, Error>(archived).unwrap();
        assert_eq!(deserialized, value);

        let mut rng = rand::thread_rng();

        {
            // https://rkyv.org/format.html says:
            // This deterministic layout means that you don't need to store the position of
            // the root object in most cases. As long as your buffer ends right at the end of
            // your root object, you can use `access` with your buffer.

            // Thus left padding should work.  We add 1024 bytes of random junk to the left.

            let mut left_padded_bytes = vec![0; 1024];
            rng.fill(&mut left_padded_bytes[..]);
            // Then add our original bytes to the end:
            left_padded_bytes.extend_from_slice(&bytes);

            // we should be able to access as before:
            let archived2 = rkyv::access::<ArchivedTest, Error>(&left_padded_bytes[..]).unwrap();
            assert_eq!(archived2, &value);
        }
        {
            // The same but right padding junk should fail:
            let mut right_padded_bytes = bytes.clone();
            let mut junk = vec![0; 1024];
            rng.fill(&mut junk[..]);
            right_padded_bytes.extend_from_slice(&junk);
            // we should not be able to access as before:
            let _ = rkyv::access::<ArchivedTest, Error>(&right_padded_bytes[..])
                .expect_err("This should fail.");
        }
    }
}
