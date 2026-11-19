# Digital Signatures and Incremental Updates

pypdf can inspect signed PDFs and the incremental updates appended to them.
This is a structural analysis: it checks the signature's `/ByteRange`, verifies
the CMS `messageDigest` signed attribute when present, and reports bytes which
the signature does not cover. It does not validate certificate chains or the
signer's public-key signature.

```python
from pypdf import PdfReader

reader = PdfReader("signed.pdf")

for revision in reader.revisions:
    print(revision.revision_number, revision.xref_offset, revision.byte_range)

for update in reader.incremental_updates:
    print("incremental update", update.byte_range)

for signature in reader.signatures:
    print(signature.field_name)
    print(signature.byte_range)
    print(signature.covered_ranges)
    print(signature.unsigned_ranges)
    print(signature.covers_entire_file)
    print(signature.digest_valid)
    print(signature.is_tampered)
```

`digest_valid` is `True` or `False` when the CMS message digest can be parsed,
and `None` when the signature format does not expose one. A signature can have a
valid digest and still leave bytes uncovered: `modified_after_signing` is then
`True`. Use `incremental_updates_after_signing` to distinguish a structurally
valid update from data which could not be parsed as a revision.

`is_tampered` is `True` for invalid byte ranges, a CMS message-digest mismatch,
or an uncovered tail which does not form a valid incremental update. Whether a
valid incremental update after signing is acceptable depends on the signature
policy of the application.
