"""Incremental-update and digital-signature inspection helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .generic import (
    ArrayObject,
    ByteStringObject,
    DictionaryObject,
    IndirectObject,
    PdfObject,
    TextStringObject,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

_WHITESPACE = b"\x00\t\n\f\r "
_STARTXREF = re.compile(
    rb"startxref[" + _WHITESPACE + rb"]+(\d+)[" + _WHITESPACE + rb"]+%%EOF"
)


@dataclass(frozen=True)
class _RevisionRecord:
    """Raw revision information collected while the xref chain is read."""

    xref_offset: int
    trailer: DictionaryObject
    previous_xref_offset: int | None


@dataclass(frozen=True)
class PdfRevision:
    """One revision in a PDF's incremental-update chain.

    The first revision is the original document. Every following revision
    was appended as an incremental update. Byte offsets use Python slice
    semantics: ``start_offset`` is inclusive and ``end_offset`` is exclusive.
    """

    index: int
    xref_offset: int
    start_offset: int
    end_offset: int
    trailer: DictionaryObject = field(compare=False, repr=False)
    previous_xref_offset: int | None = None

    @property
    def offset(self) -> int:
        """Alias for :attr:`xref_offset`."""
        return self.xref_offset

    @property
    def start(self) -> int:
        """Byte offset at which this revision starts."""
        return self.start_offset

    @property
    def end(self) -> int:
        """Byte offset just after this revision."""
        return self.end_offset

    @property
    def size(self) -> int:
        """Number of bytes in this revision."""
        return self.end_offset - self.start_offset

    @property
    def byte_range(self) -> tuple[int, int]:
        """The revision as a ``(start, end)`` byte range."""
        return self.start_offset, self.end_offset

    @property
    def revision_number(self) -> int:
        """One-based revision number."""
        return self.index + 1

    @property
    def is_incremental(self) -> bool:
        """Whether this revision was appended to an earlier one."""
        return self.index > 0

    def contains(self, offset: int) -> bool:
        """Return whether ``offset`` belongs to this revision."""
        return self.start_offset <= offset < self.end_offset


class PdfSignature:
    """A digital signature embedded in a PDF document.

    This class inspects the signature dictionary and its ``/ByteRange``. It
    verifies the CMS ``messageDigest`` signed attribute when it can be parsed,
    but does not validate the signer certificate chain or the cryptographic
    signature itself.
    """

    def __init__(
        self,
        *,
        field_name: str | None,
        field: DictionaryObject | None,
        signature_dictionary: DictionaryObject,
        data: bytes,
        revisions: Sequence[PdfRevision],
    ) -> None:
        self.field_name = field_name
        self.field = field
        self.signature_dictionary = signature_dictionary
        self._data = data
        self.file_size = len(data)

        raw_byte_range = signature_dictionary.get("/ByteRange")
        if isinstance(raw_byte_range, IndirectObject):
            raw_byte_range = raw_byte_range.get_object()
        self.byte_range, self._byte_range_errors = _parse_byte_range(
            raw_byte_range, self.file_size
        )
        self.covered_ranges = _covered_ranges(self.byte_range)
        self.covered_length = sum(end - start for start, end in self.covered_ranges)
        self.excluded_ranges = _complement_ranges(
            self.covered_ranges, self.file_size
        )

        self.signature_contents_range = _signature_contents_range(
            self.covered_ranges, self.excluded_ranges, self.file_size
        )
        self.unsigned_ranges = tuple(
            byte_range
            for byte_range in self.excluded_ranges
            if byte_range != self.signature_contents_range
        )

        contents = signature_dictionary.get("/Contents")
        if isinstance(contents, IndirectObject):
            contents = contents.get_object()
        if isinstance(contents, (ByteStringObject, bytes, bytearray)):
            self.contents = bytes(contents)
        elif isinstance(contents, TextStringObject):
            self.contents = contents.original_bytes
        else:
            self.contents = b""

        self.digest_algorithm, digests = _cms_message_digests(self.contents)
        self.digest_valid: bool | None
        if not self._byte_range_errors and digests:
            covered_data = self.covered_data
            self.digest_valid = all(
                _digest_matches(algorithm, covered_data, digest)
                for algorithm, digest in digests
            )
        elif digests:
            self.digest_valid = False
        else:
            self.digest_valid = None

        coverage_end = max(
            (end for _start, end in self.covered_ranges), default=0
        )
        self.coverage_end = coverage_end
        self.coverage_ratio = (
            self.covered_length / self.file_size if self.file_size else 0.0
        )
        self.covers_entire_file = bool(
            self.covered_ranges
            and self.covered_ranges[0][0] == 0
            and self.coverage_end == self.file_size
            and not self.unsigned_ranges
        )
        self.modified_after_signing = coverage_end < self.file_size

        self.signed_revision = _find_signed_revision(revisions, coverage_end)
        if self.signed_revision is None:
            self.incremental_updates_after_signing: tuple[PdfRevision, ...] = ()
        else:
            self.incremental_updates_after_signing = tuple(
                revision
                for revision in revisions
                if revision.index > self.signed_revision.index
            )

        reasons = list(self._byte_range_errors)
        if self.digest_valid is False:
            reasons.append(
                "The signed byte ranges do not match the CMS message digest."
            )
        if self.modified_after_signing and not self.incremental_updates_after_signing:
            trailing = self.file_size - coverage_end
            reasons.append(
                f"{trailing} byte(s) after the signed range are not covered "
                "and do not form a valid incremental update."
            )
        if self.unsigned_ranges and not self.modified_after_signing:
            reasons.append("The signature does not cover the whole document.")
        self.tamper_reasons = tuple(reasons)
        self.is_tampered = bool(self.tamper_reasons)

    @property
    def byte_range_valid(self) -> bool:
        """Whether ``/ByteRange`` is structurally valid."""
        return not self._byte_range_errors

    @property
    def byte_range_errors(self) -> tuple[str, ...]:
        """Reasons why ``/ByteRange`` is invalid."""
        return self._byte_range_errors

    @property
    def covered_data(self) -> bytes:
        """The bytes covered by the signature."""
        return b"".join(
            self._data[start:end] for start, end in self.covered_ranges
        )

    @property
    def signed_data(self) -> bytes:
        """Alias for :attr:`covered_data`."""
        return self.covered_data

    @property
    def coverage(self) -> float:
        """Fraction of the file covered by the signature."""
        return self.coverage_ratio

    @property
    def covers_entire_document(self) -> bool:
        """Alias for :attr:`covers_entire_file`."""
        return self.covers_entire_file

    @property
    def has_incremental_updates(self) -> bool:
        """Whether revisions were appended after the signed revision."""
        return bool(self.incremental_updates_after_signing)

    @property
    def has_uncovered_changes(self) -> bool:
        """Whether any bytes are outside the signed byte ranges."""
        return bool(self.unsigned_ranges) or self.modified_after_signing

    @property
    def revision_index(self) -> int | None:
        """Index of the signed revision, or ``None`` if it cannot be located."""
        return None if self.signed_revision is None else self.signed_revision.index

    @property
    def filter(self) -> str | None:
        """The signature handler name from ``/Filter``."""
        return _string_value(self.signature_dictionary.get("/Filter"))

    @property
    def sub_filter(self) -> str | None:
        """The signature encoding from ``/SubFilter``."""
        return _string_value(self.signature_dictionary.get("/SubFilter"))

    @property
    def signing_time(self) -> str | None:
        """The raw signing time from ``/M``."""
        return _string_value(self.signature_dictionary.get("/M"))

    @property
    def reason(self) -> str | None:
        """The signing reason from ``/Reason``."""
        return _string_value(self.signature_dictionary.get("/Reason"))

    @property
    def location(self) -> str | None:
        """The signing location from ``/Location``."""
        return _string_value(self.signature_dictionary.get("/Location"))

    @property
    def contact_info(self) -> str | None:
        """The signer contact information from ``/ContactInfo``."""
        return _string_value(self.signature_dictionary.get("/ContactInfo"))

    @property
    def tampered(self) -> bool:
        """Alias for :attr:`is_tampered`."""
        return self.is_tampered

    def __repr__(self) -> str:
        return (
            f"PdfSignature(field_name={self.field_name!r}, "
            f"byte_range={self.byte_range!r}, "
            f"is_tampered={self.is_tampered!r})"
        )


def build_revisions(
    records: Sequence[_RevisionRecord], data: bytes
) -> list[PdfRevision]:
    """Turn xref-chain records into oldest-first revisions with byte boundaries."""
    if not records:
        return []

    oldest_first = list(reversed(records))
    eof_offsets = _find_eof_offsets(data)
    starts: list[int] = [0]
    for index in range(1, len(oldest_first)):
        previous = oldest_first[index - 1]
        eof_end = eof_offsets.get(previous.xref_offset)
        if eof_end is None:
            starts.append(oldest_first[index].xref_offset)
            continue
        next_start = eof_end
        while next_start < len(data) and data[next_start] in _WHITESPACE:
            next_start += 1
        starts.append(max(next_start, starts[-1]))

    revisions: list[PdfRevision] = []
    for index, record in enumerate(oldest_first):
        end_offset = starts[index + 1] if index + 1 < len(starts) else len(data)
        revisions.append(
            PdfRevision(
                index=index,
                xref_offset=record.xref_offset,
                start_offset=starts[index],
                end_offset=end_offset,
                trailer=record.trailer,
                previous_xref_offset=record.previous_xref_offset,
            )
        )
    return revisions


def extract_signatures(
    reader: Any, data: bytes, revisions: Sequence[PdfRevision]
) -> list[PdfSignature]:
    """Extract all signed signature fields from ``reader``."""
    signatures: list[PdfSignature] = []
    seen_signature_ids: set[int] = set()

    try:
        root = reader.root_object
        acro_form = root.get("/AcroForm")
        if acro_form is not None:
            acro_form = acro_form.get_object()
    except Exception:
        acro_form = None

    if isinstance(acro_form, DictionaryObject):
        fields = acro_form.get("/Fields")
        if isinstance(fields, IndirectObject):
            fields = fields.get_object()
        if isinstance(fields, ArrayObject):
            _walk_signature_fields(
                reader,
                fields,
                signatures,
                seen_signature_ids,
                data,
                revisions,
            )

    if not signatures:
        signatures.extend(
            _scan_for_signature_dictionaries(reader, data, revisions)
        )
    return signatures


def _walk_signature_fields(
    reader: Any,
    fields: ArrayObject,
    signatures: list[PdfSignature],
    seen_signature_ids: set[int],
    data: bytes,
    revisions: Sequence[PdfRevision],
    inherited_type: str | None = None,
    inherited_signature: PdfObject | None = None,
    parent_name: str = "",
    seen_fields: set[int] | None = None,
) -> None:
    if seen_fields is None:
        seen_fields = set()

    for field_reference in fields:
        field_object = field_reference.get_object()
        if not isinstance(field_object, DictionaryObject):
            continue

        field_id = id(field_object)
        if field_id in seen_fields:
            continue
        seen_fields.add(field_id)

        field_type = _string_value(field_object.get("/FT")) or inherited_type
        field_value = field_object.get("/V")
        if field_value is None:
            field_value = inherited_signature

        name = _string_value(field_object.get("/T"))
        full_name = (
            f"{parent_name}.{name}" if parent_name and name else name or parent_name
        )

        if field_type == "/Sig" and field_value is not None:
            signature_dictionary = field_value.get_object()
            if isinstance(signature_dictionary, DictionaryObject):
                signature_id = id(signature_dictionary)
                if signature_id not in seen_signature_ids:
                    seen_signature_ids.add(signature_id)
                    signatures.append(
                        PdfSignature(
                            field_name=full_name or None,
                            field=field_object,
                            signature_dictionary=signature_dictionary,
                            data=data,
                            revisions=revisions,
                        )
                    )

        kids = field_object.get("/Kids")
        if isinstance(kids, IndirectObject):
            kids = kids.get_object()
        if isinstance(kids, ArrayObject):
            _walk_signature_fields(
                reader,
                kids,
                signatures,
                seen_signature_ids,
                data,
                revisions,
                inherited_type=field_type,
                inherited_signature=field_value,
                parent_name=full_name,
                seen_fields=seen_fields,
            )


def _scan_for_signature_dictionaries(
    reader: Any, data: bytes, revisions: Sequence[PdfRevision]
) -> list[PdfSignature]:
    """Fallback for malformed files without a usable AcroForm field tree."""
    signatures: list[PdfSignature] = []
    seen: set[int] = set()
    xref = getattr(reader, "xref", {})
    for generation, generation_map in xref.items():
        if generation == 65535:
            continue
        for object_number in generation_map:
            try:
                obj = IndirectObject(object_number, generation, reader).get_object()
            except Exception:  # noqa: S112
                continue
            if not isinstance(obj, DictionaryObject):
                continue
            if obj.get("/Type") != "/Sig" and obj.get("/FT") != "/Sig":
                continue
            signature_dictionary = obj.get("/V") if obj.get("/FT") == "/Sig" else obj
            if signature_dictionary is None:
                continue
            signature_dictionary = signature_dictionary.get_object()
            if not isinstance(signature_dictionary, DictionaryObject):
                continue
            if "/ByteRange" not in signature_dictionary:
                continue
            signature_id = id(signature_dictionary)
            if signature_id in seen:
                continue
            seen.add(signature_id)
            signatures.append(
                PdfSignature(
                    field_name=_string_value(obj.get("/T")),
                    field=obj if obj.get("/FT") == "/Sig" else None,
                    signature_dictionary=signature_dictionary,
                    data=data,
                    revisions=revisions,
                )
            )
    return signatures


def _find_eof_offsets(data: bytes) -> dict[int, int]:
    """Map each ``startxref`` pointer to the end of its corresponding ``%%EOF``."""
    offsets: dict[int, int] = {}
    for match in _STARTXREF.finditer(data):
        offsets[int(match.group(1))] = match.end()
    return offsets


def _parse_byte_range(
    raw_byte_range: Any, file_size: int
) -> tuple[tuple[int, int, int, int], tuple[str, ...]]:
    errors: list[str] = []
    values: list[int] = []
    if not isinstance(raw_byte_range, (ArrayObject, list, tuple)):
        return (0, 0, 0, 0), ("/ByteRange is missing or is not an array.",)

    try:
        values = [int(value) for value in raw_byte_range]
    except (TypeError, ValueError):
        return (0, 0, 0, 0), ("/ByteRange contains a non-integer value.",)

    if len(values) != 4:
        errors.append("/ByteRange must contain exactly two start/length pairs.")
    if any(value < 0 for value in values):
        errors.append("/ByteRange contains a negative value.")

    pairs = [
        (values[index], values[index + 1])
        for index in range(0, len(values) - 1, 2)
    ]
    if pairs and pairs[0][0] != 0:
        errors.append("/ByteRange does not start at offset 0.")

    previous_end = 0
    for start, length in pairs:
        end = start + length
        if length < 0 or start < 0 or end < start:
            errors.append("/ByteRange contains an invalid interval.")
            continue
        if end > file_size:
            errors.append("/ByteRange extends beyond the end of the file.")
        if start < previous_end:
            errors.append("/ByteRange intervals overlap or are not ordered.")
        previous_end = max(previous_end, end)

    if len(pairs) == 2:
        first_start, first_length = pairs[0]
        second_start, second_length = pairs[1]
        return (
            (first_start, first_length, second_start, second_length),
            tuple(errors),
        )
    if len(values) == 4:
        return (values[0], values[1], values[2], values[3]), tuple(errors)
    return (0, 0, 0, 0), tuple(errors)


def _covered_ranges(
    byte_range: tuple[int, int, int, int]
) -> tuple[tuple[int, int], ...]:
    start1, length1, start2, length2 = byte_range
    ranges = []
    if length1:
        ranges.append((start1, start1 + length1))
    if length2:
        ranges.append((start2, start2 + length2))
    return tuple(ranges)


def _complement_ranges(
    covered: Sequence[tuple[int, int]], file_size: int
) -> tuple[tuple[int, int], ...]:
    gaps: list[tuple[int, int]] = []
    cursor = 0
    for start, end in covered:
        if cursor < start:
            gaps.append((cursor, min(start, file_size)))
        cursor = max(cursor, end)
    if cursor < file_size:
        gaps.append((cursor, file_size))
    return tuple(gap for gap in gaps if gap[0] < gap[1])


def _signature_contents_range(
    covered: Sequence[tuple[int, int]],
    excluded: Sequence[tuple[int, int]],
    file_size: int,
) -> tuple[int, int] | None:
    if len(covered) >= 2:
        candidate = (covered[0][1], covered[1][0])
        if candidate[0] < candidate[1] <= file_size:
            return candidate
    for gap in excluded:
        if gap[1] < file_size:
            return gap
    return None


def _find_signed_revision(
    revisions: Sequence[PdfRevision], coverage_end: int
) -> PdfRevision | None:
    if not revisions:
        return None
    for revision in revisions:
        if revision.start_offset <= coverage_end <= revision.end_offset:
            return revision
    return revisions[-1] if coverage_end >= revisions[-1].end_offset else None


def _string_value(value: Any) -> str | None:
    if value is None:
        return None
    value = value.get_object() if isinstance(value, IndirectObject) else value
    if isinstance(value, (TextStringObject, str)):
        return str(value)
    return None


def _cms_message_digests(
    contents: bytes,
) -> tuple[str | None, tuple[tuple[str, bytes], ...]]:
    """Extract ``(hash_name, messageDigest)`` pairs from CMS SignedData."""
    try:
        data = contents.rstrip(b"\x00")
        _tag, start, end, _next = _read_der(data, 0)
        root_children = list(_der_children(data, start, end))
        if len(root_children) < 2:
            return None, ()
        oid_tag, oid_start, oid_end = root_children[0]
        if oid_tag != 0x06 or _decode_oid(data[oid_start:oid_end]) != "1.2.840.113549.1.7.2":
            return None, ()

        explicit_tag, explicit_start, _explicit_end = root_children[1]
        if explicit_tag != 0xA0:
            return None, ()
        _tag, signed_data_start, signed_data_end, _next = _read_der(
            data, explicit_start
        )
        signed_data_children = list(
            _der_children(data, signed_data_start, signed_data_end)
        )
        if not signed_data_children:
            return None, ()
        signer_set_tag, signer_set_start, signer_set_end = signed_data_children[-1]
        if signer_set_tag != 0x31:
            return None, ()

        algorithm: str | None = None
        digests: list[tuple[str, bytes]] = []
        for signer_tag, signer_start, signer_end in _der_children(
            data, signer_set_start, signer_set_end
        ):
            if signer_tag != 0x30:
                continue
            signer_children = list(_der_children(data, signer_start, signer_end))
            if len(signer_children) < 4:
                continue
            digest_algorithm = signer_children[2]
            if digest_algorithm[0] != 0x30:
                continue
            algorithm_children = list(
                _der_children(data, digest_algorithm[1], digest_algorithm[2])
            )
            if not algorithm_children or algorithm_children[0][0] != 0x06:
                continue
            algorithm_oid = _decode_oid(
                data[algorithm_children[0][1]:algorithm_children[0][2]]
            )
            hash_name = _HASH_OIDS.get(algorithm_oid)
            if hash_name is None:
                continue
            algorithm = algorithm or hash_name

            signed_attributes = next(
                (
                    child
                    for child in signer_children
                    if child[0] == 0xA0
                ),
                None,
            )
            if signed_attributes is None:
                continue
            message_digest = _find_message_digest(
                data, signed_attributes[1], signed_attributes[2]
            )
            if message_digest is not None:
                digests.append((hash_name, message_digest))
        return algorithm, tuple(digests)
    except (IndexError, ValueError):
        return None, ()


def _find_message_digest(data: bytes, start: int, end: int) -> bytes | None:
    for attribute_tag, attribute_start, attribute_end in _der_children(
        data, start, end
    ):
        if attribute_tag != 0x30:
            continue
        attribute_children = list(
            _der_children(data, attribute_start, attribute_end)
        )
        if len(attribute_children) < 2:
            continue
        oid_tag, oid_start, oid_end = attribute_children[0]
        if (
            oid_tag != 0x06
            or _decode_oid(data[oid_start:oid_end])
            != "1.2.840.113549.1.9.4"
        ):
            continue
        value_tag, value_start, value_end = attribute_children[1]
        if value_tag != 0x31:
            continue
        for digest_tag, digest_start, digest_end in _der_children(
            data, value_start, value_end
        ):
            if digest_tag == 0x04:
                return data[digest_start:digest_end]
    return None


def _read_der(data: bytes, position: int) -> tuple[int, int, int, int]:
    if position + 2 > len(data):
        raise ValueError("truncated DER value")
    tag = data[position]
    position += 1
    first_length = data[position]
    position += 1
    if first_length & 0x80:
        length_octets = first_length & 0x7F
        if length_octets == 0 or length_octets > 8:
            raise ValueError("unsupported DER length")
        if position + length_octets > len(data):
            raise ValueError("truncated DER length")
        length = int.from_bytes(
            data[position:position + length_octets], "big"
        )
        position += length_octets
    else:
        length = first_length
    value_end = position + length
    if value_end > len(data):
        raise ValueError("truncated DER value")
    return tag, position, value_end, value_end


def _der_children(
    data: bytes, start: int, end: int
) -> Iterator[tuple[int, int, int]]:
    position = start
    while position < end:
        tag, value_start, value_end, next_position = _read_der(data, position)
        if next_position > end:
            raise ValueError("DER child exceeds its parent")
        yield tag, value_start, value_end
        position = next_position


def _decode_oid(raw_oid: bytes) -> str:
    if not raw_oid:
        return ""
    values = [raw_oid[0] // 40, raw_oid[0] % 40]
    value = 0
    for octet in raw_oid[1:]:
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            values.append(value)
            value = 0
    return ".".join(str(value) for value in values)


def _digest_matches(algorithm: str, data: bytes, expected: bytes) -> bool:
    try:
        return hashlib.new(algorithm, data).digest() == expected
    except ValueError:
        return True


_HASH_OIDS = {
    "1.2.840.113549.2.5": "md5",
    "1.3.14.3.2.26": "sha1",
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
    "2.16.840.1.101.3.4.2.4": "sha224",
    "2.16.840.1.101.3.4.2.5": "sha512_224",
    "2.16.840.1.101.3.4.2.6": "sha512_256",
    "2.16.840.1.101.3.4.2.7": "sha3_224",
    "2.16.840.1.101.3.4.2.8": "sha3_256",
    "2.16.840.1.101.3.4.2.9": "sha3_384",
    "2.16.840.1.101.3.4.2.10": "sha3_512",
}


__all__ = [
    "PdfRevision",
    "PdfSignature",
    "build_revisions",
    "extract_signatures",
]
