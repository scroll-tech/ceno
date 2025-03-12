use ff_ext::ExtensionField;

use transcript::Transcript;

use crate::basefold::Digest;

pub fn write_digest_to_transcript<E: ExtensionField>(
    digest: &Digest<E>,
    transcript: &mut impl Transcript<E>,
) {
    digest
        .as_ref()
        .iter()
        .for_each(|x| transcript.append_field_element(x));
}
