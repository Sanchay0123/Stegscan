import os
from zipfile import ZipFile
from PyPDF2 import PdfReader

def extract_images_from_pdf(path, out_dir="reports/extracted"):
    os.makedirs(out_dir, exist_ok=True)
    imgs = []
    try:
        reader = PdfReader(open(path, "rb"))
    except Exception:
        return imgs
    idx = 0
    for pnum, page in enumerate(reader.pages):
        try:
            resources = page.get("/Resources")
            if not resources: continue
            xobj = resources.get("/XObject")
            if not xobj: continue
            for name, obj in xobj.items():
                try:
                    sub = obj.get_object()
                    if sub.get("/Subtype") == "/Image":
                        data = sub.get_data()
                        fmt = "bin"
                        f = sub.get("/Filter")
                        if f == "/DCTDecode": fmt = "jpg"
                        elif f == "/FlateDecode": fmt = "png"
                        elif f == "/JPXDecode": fmt = "jp2"
                        out_path = os.path.join(out_dir, f"pdf_{os.path.basename(path)}_{pnum}_{idx}.{fmt}")
                        with open(out_path, "wb") as fh: fh.write(data)
                        imgs.append(out_path); idx += 1
                except Exception:
                    continue
        except Exception:
            continue
    return imgs

def extract_images_from_docx(path, out_dir="reports/extracted"):
    os.makedirs(out_dir, exist_ok=True)
    imgs = []
    try:
        with ZipFile(path, 'r') as z:
            for name in z.namelist():
                if name.startswith("word/media/"):
                    data = z.read(name)
                    out_path = os.path.join(out_dir, f"{os.path.basename(path)}_{os.path.basename(name)}")
                    with open(out_path, "wb") as f: f.write(data)
                    imgs.append(out_path)
    except Exception:
        pass
    return imgs

def extract_all(path):
    ext = os.path.splitext(path)[1].lower()
    out = {"images": [], "is_pdf": False, "is_docx": False, "is_doc": False}
    if ext in [".png",".jpg",".jpeg",".bmp",".gif",".tif",".tiff"]:
        out["images"].append(path)
    elif ext == ".pdf":
        out["is_pdf"] = True
        out["images"].extend(extract_images_from_pdf(path))
    elif ext in [".docx", ".docm"]:
        out["is_docx"] = True
        out["images"].extend(extract_images_from_docx(path))
    elif ext == ".doc":
        out["is_doc"] = True
        # images in legacy .doc are harder; rely on docx_analysis for macros/embeds
    return out

