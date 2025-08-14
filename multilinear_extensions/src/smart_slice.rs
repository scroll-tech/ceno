use serde::{Deserialize, Deserializer, Serialize};
use std::{
    hash::{Hash, Hasher},
    ops::{Deref, DerefMut},
};

/// a flexible enum similar to `std::borrow::Cow`, but supports mutable slices as a variant
///
/// `std::Cow` allows either borrowed (`&T`) or owned (`T::Owned`) data, but it does **not**
/// support mutable borrowed data (i.e., `&mut [T]`). This `SmartSlice` enum extends Cow-like
/// behavior by adding a third variant:
/// - `Borrowed`: a shared reference to `[T]`, like `Cow::Borrowed`
/// - `BorrowedMut`: a mutable reference to `[T]`, not supported in `Cow`
/// - `Owned`: an owned `Vec<T>`, like `Cow::Owned`
///
/// this is useful when the caller might own, share, or temporarily mutate a slice
/// and we want to abstract over all three cases while enabling mutation (via `.to_mut()`).
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum SmartSlice<'a, T> {
    Borrowed(&'a [T]),        // shared reference
    BorrowedMut(&'a mut [T]), // mutable reference
    Owned(Vec<T>),            // owned vector
}

impl<'a, T> Default for SmartSlice<'a, T> {
    fn default() -> Self {
        SmartSlice::Owned(Vec::new()) // default to empty owned vector
    }
}

impl<'a, T> SmartSlice<'a, T> {
    /// ensures the data is owned and returns a mutable slice.
    ///
    /// Panic if the data is reference borrowed
    pub fn to_mut(&mut self) -> &mut [T]
    where
        T: Clone,
    {
        match self {
            SmartSlice::Borrowed(_) => panic!("calling to_mut on immutable slice"),
            SmartSlice::BorrowedMut(slice) => slice,
            SmartSlice::Owned(vec) => vec.as_mut_slice(),
        }
    }

    /// returns an immutable slice reference
    pub fn as_slice(&self) -> &[T] {
        match self {
            SmartSlice::Borrowed(slice) => slice,
            SmartSlice::BorrowedMut(slice) => slice,
            SmartSlice::Owned(vec) => vec.as_slice(),
        }
    }

    /// returns the length of the slice
    pub fn len(&self) -> usize {
        self.as_slice().len()
    }

    /// returns true if the slice is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// clone inner vector
    pub fn to_vec(&self) -> Vec<T>
    where
        T: Clone,
    {
        match self {
            SmartSlice::Owned(vec) => vec.clone(),
            SmartSlice::Borrowed(slice) => slice.to_vec(),
            SmartSlice::BorrowedMut(slice) => slice.to_vec(),
        }
    }

    /// truncates the contents to `new_len`
    pub fn truncate_mut(&mut self, new_len: usize)
    where
        T: Clone + Default,
    {
        let new_self = match std::mem::take(self) {
            SmartSlice::Owned(mut vec) => {
                vec.truncate(new_len);
                SmartSlice::Owned(vec)
            }
            SmartSlice::BorrowedMut(slice) => {
                let len = slice.len().min(new_len);
                SmartSlice::BorrowedMut(&mut slice[..len])
            }
            SmartSlice::Borrowed(_) => panic!("truncate on immutable slice"),
        };
        *self = new_self;
    }

    /// extends contents if owned, panics on borrowed
    pub fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        match self {
            SmartSlice::Owned(vec) => vec.extend(iter),
            SmartSlice::Borrowed(_) | SmartSlice::BorrowedMut(_) => {
                panic!("cannot extend borrowed data");
            }
        }
    }
}

impl<'a, T> Deref for SmartSlice<'a, T> {
    type Target = [T];

    /// dereferences to &[T]
    fn deref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<'a, T> DerefMut for SmartSlice<'a, T>
where
    T: Clone,
{
    /// dereferences to &mut [T], converting to owned if needed
    fn deref_mut(&mut self) -> &mut [T] {
        self.to_mut()
    }
}

impl<'a, T: Clone> Clone for SmartSlice<'a, T> {
    /// clones the slice (panics on BorrowedMut)
    fn clone(&self) -> Self {
        match self {
            SmartSlice::Borrowed(slice) => SmartSlice::Borrowed(slice),
            SmartSlice::BorrowedMut(_) => {
                panic!("clone not supported on mutable slice")
            }
            SmartSlice::Owned(vec) => SmartSlice::Owned(vec.clone()),
        }
    }
}

impl<'a, T: PartialEq> PartialEq for SmartSlice<'a, T> {
    /// compares the contents of two slices
    fn eq(&self, other: &Self) -> bool {
        self.deref() == other.deref()
    }
}

impl<'a, T: Eq> Eq for SmartSlice<'a, T> {}

impl<'a, T: Hash> Hash for SmartSlice<'a, T> {
    /// hashes the contents
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.deref().hash(state)
    }
}

impl<'de, 'a, T> Deserialize<'de> for SmartSlice<'a, T>
where
    T: ToOwned,
    T: Deserialize<'de>,
{
    /// deserializes into owned Vec<T>
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<T>::deserialize(deserializer).map(SmartSlice::Owned)
    }
}

#[cfg(test)]
mod tests {
    use super::SmartSlice;

    #[test]
    fn test_smart_slice_de_ser() {
        let slice = SmartSlice::Owned(vec![1, 2, 3]);

        let slice_encoded = serde_json::to_string(&slice).unwrap();

        let slice_decoded = serde_json::from_str(&slice_encoded).unwrap();

        assert_eq!(slice, slice_decoded);
    }
}
