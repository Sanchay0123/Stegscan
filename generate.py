import os, random, string, zlib, zipfile

# ===================================================================
# Helper functions
# ===================================================================

def rand_bytes(n=200):
    return os.urandom(n)

def rand_text(n=200):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))


# ===================================================================
# PDF GENERATORS (VALID + OPEN PROPERLY)
# ===================================================================

def create_clean_pdf(path):
    objects = []

    # Object 1 - Catalog
    objects.append(b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n")

    # Object 2 - Pages
    objects.append(b"2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj\n")

    # Object 3 - Page
    objects.append(b"3 0 obj << /Type /Page /Parent 2 0 R "
                   b"/MediaBox [0 0 300 300] >> endobj\n")

    # ---------------------------
    # Build PDF with correct offsets
    # ---------------------------

    pdf = b"%PDF-1.4\n"
    offsets = [0]  # xref entry 0 is always free

    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj

    # Build xref table
    xref_pos = len(pdf)
    xref = f"xref\n0 {len(offsets)}\n".encode()

    # Entry 0 (free)
    xref += b"0000000000 65535 f \n"

    # Other entries
    for off in offsets[1:]:
        xref += f"{off:010d} 00000 n \n".encode()

    pdf += xref

    # Trailer
    trailer = f"trailer << /Size {len(offsets)} /Root 1 0 R >>\n".encode()
    pdf += trailer

    # startxref
    pdf += f"startxref\n{xref_pos}\n%%EOF".encode()

    with open(path, "wb") as f:
        f.write(pdf)


def create_stego_pdf(path):
    import os, zlib

    # ----------------------------------------------------------
    # 1. High entropy stream
    # ----------------------------------------------------------
    high_entropy = zlib.compress(os.urandom(2000))

    # ----------------------------------------------------------
    # 2. Fake embedded file data (harmless)
    # ----------------------------------------------------------
    embedded_file_content = b"THIS_IS_HARMLESS_EMBEDDED_DATA_" + os.urandom(200)

    # ----------------------------------------------------------
    # 3. Fake JavaScript object (non-executable)
    # ----------------------------------------------------------
    fake_js = b"var harmless = 'test'; // not real JS"

    # ----------------------------------------------------------
    # 4. ZIP signature inside stream
    # ----------------------------------------------------------
    fake_zip = b"PK\x03\x04" + os.urandom(300)

    objects = []

    # 1: Catalog w/ JS OpenAction
    objects.append(
        b"1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >> endobj\n"
    )

    # 2: Pages
    objects.append(
        b"2 0 obj << /Type /Pages /Count 1 /Kids [3 0 R] >> endobj\n"
    )

    # 3: Page
    objects.append(
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] >> endobj\n"
    )

    # 4: High entropy content stream
    objects.append(
        b"4 0 obj << /Length "
        + str(len(high_entropy)).encode()
        + b" /Filter /FlateDecode >> stream\n"
        + high_entropy
        + b"\nendstream\nendobj\n"
    )

    # 5: Fake JS object
    objects.append(
        b"5 0 obj << /Length "
        + str(len(fake_js)).encode()
        + b" >> stream\n"
        + fake_js
        + b"\nendstream\nendobj\n"
    )

    # 6: Embedded file object
    objects.append(
        b"6 0 obj << /Length "
        + str(len(embedded_file_content)).encode()
        + b" >> stream\n"
        + embedded_file_content
        + b"\nendstream\nendobj\n"
    )

    # 7: ZIP signature inside stream
    objects.append(
        b"7 0 obj << /Length "
        + str(len(fake_zip)).encode()
        + b" >> stream\n"
        + fake_zip
        + b"\nendstream\nendobj\n"
    )

    # 8: Names dictionary linking embedded file
    objects.append(
        b"8 0 obj << /Names << /EmbeddedFiles << /Names [(dummy.txt) 6 0 R] >> >> >> endobj\n"
    )

    # ----------------------------------------------------------
    # Build the PDF with correct xref offsets
    # ----------------------------------------------------------

    pdf = b"%PDF-1.4\n"
    offsets = [0]

    for obj in objects:
        offsets.append(len(pdf))
        pdf += obj

    xref_pos = len(pdf)
    xref = f"xref\n0 {len(offsets)}\n".encode()
    xref += b"0000000000 65535 f \n"

    for off in offsets[1:]:
        xref += f"{off:010d} 00000 n \n".encode()

    pdf += xref

    trailer = f"trailer << /Size {len(offsets)} /Root 1 0 R >>\n".encode()
    pdf += trailer

    pdf += f"startxref\n{xref_pos}\n%%EOF".encode()

    with open(path, "wb") as f:
        f.write(pdf)

# ===================================================================
# DOCX GENERATORS (VALID + OPEN PROPERLY)
# ===================================================================

def create_clean_docx(path):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml",
            """<?xml version="1.0"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>""")

        z.writestr("_rels/.rels",
            """<?xml version="1.0"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1"
    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
    Target="word/document.xml"/>
</Relationships>""")

        z.writestr("word/document.xml",
            "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>Clean document.</w:t></w:r></w:p></w:body></w:document>")

        z.writestr("word/_rels/document.xml.rels", "")


def create_stego_docx(path):
    with zipfile.ZipFile(path, "w") as z:
        # Normal DOCX base
        create_clean_docx(path)

        # Add hidden data
        z.writestr("word/embeddings/hidden.bin", rand_bytes(800))
        z.writestr("vbaProject.bin", rand_bytes(400))
        z.writestr("word/media/noise.png", rand_bytes(1024))

        # Add metadata stego
        z.writestr("docProps/custom.xml", f"<props>{rand_text(300)}</props>")



# ===================================================================
# BATCH GENERATION
# ===================================================================

def generate_dataset():
    BASE = "dataset"
    paths = [
        (f"{BASE}/pdf/clean", create_clean_pdf, "pdf"),
        (f"{BASE}/pdf/stego", create_stego_pdf, "pdf"),
        (f"{BASE}/docx/clean", create_clean_docx, "docx"),
        (f"{BASE}/docx/stego", create_stego_docx, "docx"),
    ]

    for folder, fn, ext in paths:
        os.makedirs(folder, exist_ok=True)
        print(f"Generating {folder} ...")
        for i in range(2000):
            fn(f"{folder}/{i}.{ext}")
        print(f"Finished: {folder}")

    print("\nALL DONE — Dataset generated successfully.")


# ===================================================================
# RUN THE GENERATOR
# ===================================================================

if __name__ == "__main__":
    generate_dataset()
