"""Tests for incremental updates and digital signatures."""

from io import BytesIO

import pytest

from pypdf import PdfReader, PdfWriter

from . import RESOURCE_ROOT, get_data_from_url


@pytest.mark.enable_socket
def test_signature_coverage_and_incremental_updates():
    data = get_data_from_url(name="signed-incremental.pdf")
    reader = PdfReader(BytesIO(data))

    assert len(reader.revisions) == 3
    assert [revision.index for revision in reader.revisions] == [0, 1, 2]
    assert [revision.is_incremental for revision in reader.revisions] == [
        False,
        True,
        True,
    ]
    assert reader.revisions[0].start == 0
    assert reader.revisions[-1].end == len(data)
    assert len(reader.incremental_updates) == 2

    signature = reader.signatures[0]
    assert signature.field_name == "Signature1"
    assert signature.byte_range == (0, 133563, 149949, 1355)
    assert signature.covered_ranges == ((0, 133563), (149949, 151304))
    assert signature.unsigned_ranges == ((151304, len(data)),)
    assert signature.digest_algorithm == "sha256"
    assert signature.digest_valid is True
    assert signature.covers_entire_file is False
    assert signature.modified_after_signing is True
    assert signature.has_uncovered_changes is True
    assert signature.revision_index == 1
    assert [revision.index for revision in signature.incremental_updates_after_signing] == [2]
    assert signature.is_tampered is False
    assert reader.is_signed is True
    assert reader.is_tampered is False


@pytest.mark.enable_socket
def test_signature_without_incremental_update_covers_whole_file():
    data = get_data_from_url(name="signed-incremental.pdf")
    original = PdfReader(BytesIO(data)).signatures[0]
    signed_revision_end = original.coverage_end

    reader = PdfReader(BytesIO(data[:signed_revision_end]))
    signature = reader.signatures[0]

    assert len(reader.revisions) == 2
    assert signature.byte_range == original.byte_range
    assert signature.covers_entire_file is True
    assert signature.covers_entire_document is True
    assert signature.modified_after_signing is False
    assert signature.incremental_updates_after_signing == ()
    assert signature.digest_valid is True
    assert signature.is_tampered is False
    assert reader.is_tampered is False


@pytest.mark.enable_socket
def test_signature_digest_mismatch_is_detected():
    data = get_data_from_url(name="signed-tampered.pdf")
    reader = PdfReader(BytesIO(data))
    signature = reader.signatures[0]

    assert signature.digest_valid is False
    assert signature.is_tampered is True
    assert "The signed byte ranges do not match the CMS message digest." in signature.tamper_reasons
    assert reader.is_tampered is True


@pytest.mark.enable_socket
def test_uncovered_tail_without_incremental_update_is_tampering():
    data = get_data_from_url(name="signed-incremental.pdf")
    signed_revision_end = PdfReader(BytesIO(data)).signatures[0].coverage_end
    modified = data[:signed_revision_end] + b"\nunexpected trailing data"

    reader = PdfReader(BytesIO(modified))
    signature = reader.signatures[0]

    assert signature.digest_valid is True
    assert signature.modified_after_signing is True
    assert signature.incremental_updates_after_signing == ()
    assert signature.is_tampered is True
    assert "do not form a valid incremental update" in signature.tamper_reasons[0]


def test_unsigned_signature_field_is_not_reported_as_signed():
    reader = PdfReader(RESOURCE_ROOT / "form.pdf")

    assert reader.signatures == []
    assert reader.is_signed is False
    assert reader.is_tampered is False


def test_revisions_from_writer_incremental_update():
    writer = PdfWriter(RESOURCE_ROOT / "crazyones.pdf", incremental=True)
    writer.add_metadata({"/Title": "incremental update"})
    output = BytesIO()
    writer.write(output)

    reader = PdfReader(BytesIO(output.getvalue()))
    revisions = reader.revisions

    assert len(revisions) == 2
    assert revisions[0].start == 0
    assert revisions[0].end == revisions[1].start
    assert revisions[1].end == len(output.getvalue())
    assert revisions[1].previous_xref_offset == revisions[0].xref_offset
    assert reader.incremental_updates == [revisions[1]]


def test_revisions_from_xref_stream_incremental_update():
    def entry(kind: int, offset: int, generation: int) -> bytes:
        return bytes([kind]) + offset.to_bytes(4, "big") + generation.to_bytes(2, "big")

    pdf = bytearray(b"%PDF-1.5\n")
    catalog_offset = len(pdf)
    pdf += b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    pages_offset = len(pdf)
    pdf += b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"

    first_xref_offset = len(pdf)
    first_xref = (
        entry(0, 0, 65535)
        + entry(1, catalog_offset, 0)
        + entry(1, pages_offset, 0)
        + entry(1, first_xref_offset, 0)
    )
    pdf += (
        f"3 0 obj\n<< /Type /XRef /Size 4 /Index [0 4] /W [1 4 2] "
        f"/Root 1 0 R /Length {len(first_xref)} >>\nstream\n"
    ).encode()
    pdf += first_xref + b"\nendstream\nendobj\n"
    pdf += f"startxref\n{first_xref_offset}\n%%EOF\n".encode()

    info_offset = len(pdf)
    pdf += b"4 0 obj\n<< /Producer (incremental test) >>\nendobj\n"
    second_xref_offset = len(pdf)
    second_xref = entry(1, info_offset, 0) + entry(1, second_xref_offset, 0)
    pdf += (
        f"5 0 obj\n<< /Type /XRef /Size 6 /Index [4 2] /W [1 4 2] "
        f"/Root 1 0 R /Info 4 0 R /Prev {first_xref_offset} "
        f"/Length {len(second_xref)} >>\nstream\n"
    ).encode()
    pdf += second_xref + b"\nendstream\nendobj\n"
    pdf += f"startxref\n{second_xref_offset}\n%%EOF\n".encode()

    reader = PdfReader(BytesIO(pdf))

    assert len(reader.revisions) == 2
    assert reader.revisions[0].xref_offset == first_xref_offset
    assert reader.revisions[1].xref_offset == second_xref_offset
    assert reader.revisions[1].previous_xref_offset == first_xref_offset
    assert reader.metadata.producer == "incremental test"
