#!/usr/bin/env python3
import argparse
import json
import os
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import track

from utils.extractor import extract_all
from detectors.image_lsb import analyze_image
from detectors.jpeg_dct import analyze_jpeg_dct
from detectors.pdf_analysis import analyze_pdf_streams
from detectors.docx_analysis import analyze_docx_embeds
from detectors.png_chunk import analyze_png_chunks
from utils.report import save_report
from utils.extract_payload import extract_zip_from_png
from detectors.file_append import analyze_file_append

console = Console()

BANNER = r"""
███████╗████████╗███████╗ ██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔════╝╚══██╔══╝██╔════╝██╔════╝ ██╔════╝██╔════╝██╔══██╗████╗  ██║
███████╗   ██║   █████╗  ██║  ███╗███████╗██║     ███████║██╔██╗ ██║
╚════██║   ██║   ██╔══╝  ██║   ██║╚════██║██║     ██╔══██║██║╚██╗██║
███████║   ██║   ███████╗╚██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
╚══════╝   ╚═╝   ╚══════╝ ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝ 
                                                                                  
"""

# ---------------------------------------------------------------------------
# Numeric threshold configuration
# ---------------------------------------------------------------------------

# Fallback default threshold (from eval best_F1)
OPT_THRESHOLD = 0.2

THR_PATHS = [
    "reports/eval_fixed/optimal_threshold.json",
    "reports/eval_new/optimal_threshold.json",
    "reports/eval/optimal_threshold.json",
]

for p in THR_PATHS:
    if os.path.exists(p):
        try:
            with open(p, "r") as _fh:
                data = json.load(_fh)
            thr_raw = float(data.get("threshold", OPT_THRESHOLD))

            # only accept if in [0,1]; otherwise ignore this file
            if 0.0 <= thr_raw <= 1.0:
                OPT_THRESHOLD = thr_raw
                # console.log(f"[cyan]Loaded optimal threshold from {p}:[/cyan] {OPT_THRESHOLD}")  # For debugging
                break
            else:
                # console.log(
                #     f"[yellow]Warning:[/yellow] threshold {thr_raw} from {p} "
                #     f"is outside [0,1]; ignoring this file"
                # )
                pass
        except Exception as e:
            console.log(f"[yellow]Warning:[/yellow] failed to load threshold from {p}: {e}")
            # keep existing OPT_THRESHOLD and try next


# ---------------------------------------------------------------------------
# Scoring helpers (image, PDF, DOCX)
# ---------------------------------------------------------------------------

def _image_score(results: dict) -> float:
    """
    Your existing image numeric score logic, unchanged in behaviour.
    """

    # >>>>>>>>>>>>>>>>>>  TECHNIQUE WEIGHTS HERE  <<<<<<<<<<<<<<<<<<<<<<
    W_LSB = 1.0      # LSB analysis
    W_DCT = 1.0      # JPEG DCT analysis
    W_APP = 1.5      # appended file detector (strong evidence)
    W_PNG = 0.5      # PNG chunk anomalies (weaker by design now)
    # total weight for normalisation
    W_SUM = W_LSB + W_DCT + W_APP + W_PNG
    # >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

    total = 0.0
    images_count = 0

    for im in results.get("images_results", []):
        images_count += 1
        lsb_data = im.get("lsb", {}) or {}
        dct_data = im.get("dct", {}) or {}
        app_data = im.get("append", {}) or {}
        png_data = im.get("pngchunks", {}) or {}

        try:
            lsb = float(lsb_data.get("suspicious_score", 0.0) or 0.0)
        except Exception:
            lsb = 0.0
        try:
            dct = float(dct_data.get("dct_suspicion", 0.0) or 0.0)
        except Exception:
            dct = 0.0
        try:
            app = float(app_data.get("suspicion", 0.0) or 0.0)
        except Exception:
            app = 0.0
        try:
            png = float(png_data.get("suspicion", 0.0) or 0.0)
        except Exception:
            png = 0.0

        # clip each detector to [0,1]
        c_lsb = min(1.0, max(0.0, lsb))
        c_dct = min(1.0, max(0.0, dct))
        c_app = min(1.0, max(0.0, app))
        c_png = min(1.0, max(0.0, png))

        num = (
            W_LSB * c_lsb +
            W_DCT * c_dct +
            W_APP * c_app +
            W_PNG * c_png
        )

        score_im = num / W_SUM
        score_im = max(0.0, min(1.0, score_im))
        total += score_im

    if images_count == 0:
        return 0.0

    numeric = total / images_count
    return max(0.0, min(1.0, float(numeric)))


def _pdf_score(pdf_streams: dict | None) -> float:
    """
    Numeric score from PDF object streams.

    - entropy >= 7.8 → anomaly
    - magic_hit True → strong evidence (embedded exe/zip/etc.)
    """
    if not pdf_streams:
        return 0.0

    streams = pdf_streams.get("streams") or []
    if not streams:
        return 0.0

    susp_total = 0.0
    for s in streams:
        ent = float(s.get("entropy", 0.0) or 0.0)
        magic = bool(s.get("magic_hit", False))
        local = 0.0
        if ent >= 7.8:
            local += 0.4
        if magic:
            local += 0.8
        susp_total += min(1.0, local)

    avg = susp_total / len(streams)
    return max(0.0, min(1.0, avg))


def _docx_score(docx_info: dict | None) -> float:
    """
    Numeric score from DOCX embeds + macros.

    - high-entropy embedded binaries / suspicious_ext / dangerous extensions
    - macros present
    """
    if not docx_info:
        return 0.0

    embeds = docx_info.get("embeds") or []
    macros = docx_info.get("macros") or {}

    susp_total = 0.0
    n_parts = 0

    # embedded objects
    for e in embeds:
        n_parts += 1
        ent = float(e.get("entropy", 0.0) or 0.0)
        susp_ext = bool(e.get("suspicious_ext", False))
        name = str(e.get("name", "")).lower()

        local = 0.0
        if ent >= 7.8:
            local += 0.4
        if susp_ext or name.endswith((".exe", ".dll", ".js", ".vbs", ".bat", ".ps1")):
            local += 0.8

        susp_total += min(1.0, local)

    # macros
    if macros.get("has_macros"):
        n_parts += 1
        local = 0.6
        susp_total += min(1.0, local)

    if n_parts == 0:
        return 0.0

    avg = susp_total / n_parts
    return max(0.0, min(1.0, avg))


def compute_numeric_score(results: dict) -> float:
    """
    Final numeric score in [0, 1] combining:

      - image_score
      - pdf_score
      - docx_score

    This is where relative influence of images vs PDF vs DOCX is set.
    """

    img_s = _image_score(results)
    pdf_s = _pdf_score(results.get("pdf_streams"))
    docx_s = _docx_score(results.get("docx"))

    # ------------- CROSS-TYPE WEIGHTS (tune if needed) -------------
    W_IMG = 1.0
    W_PDF = 1.0
    W_DOCX = 1.0
    # ---------------------------------------------------------------

    parts = []
    weights = []

    parts.append(img_s)
    weights.append(W_IMG)

    if pdf_s > 0.0:
        parts.append(pdf_s)
        weights.append(W_PDF)

    if docx_s > 0.0:
        parts.append(docx_s)
        weights.append(W_DOCX)

    if not parts:
        return 0.0

    num = sum(w * s for w, s in zip(weights, parts))
    den = sum(weights) if weights else 1.0
    final = num / den
    return max(0.0, min(1.0, float(final)))


def classify(findings: dict):
    import os
    score = 0.0
    reasons = []

    # Image-level analysis
    for f in findings.get("images_results", []):
        img_name = os.path.basename(f.get("image", "image"))
        lsb = f.get("lsb", {})
        dct = f.get("dct", {})
        append = f.get("append", {})
        pngchunks = f.get("pngchunks", {})

        if lsb.get("suspicious_score", 0) > 0.7:
            score += 1
            reasons.append(f"LSB anomaly ({img_name})")

        if dct.get("dct_suspicion", 0) > 0.65:
            score += 1
            reasons.append(f"DCT coefficient anomaly ({img_name})")

        if append.get("found", False) or append.get("suspicion", 0) > 0.6:
            score += 1
            reasons.append(f"Appended hidden data ({img_name})")

        # PNG chunk analysis (single if block, as required)
        findings_png = pngchunks.get("findings") or []
        susp = pngchunks.get("suspicion", 0.0) or 0.0

        if findings_png or susp > 0.3:
            chunk_info = ", ".join(findings_png) or "non-standard PNG metadata structure"

            # strong embedded file signatures = high confidence
            if any(
                kw in chunk_info.lower()
                for kw in ["exe in chunk", "zip in chunk", "pdf in chunk"]
            ):
                score += 2
                reasons.append(
                    f"PNG chunk-based steganography detected ({img_name}) → {chunk_info}"
                )
            # moderate anomalies (high suspicion, but no explicit exe/zip/pdf)
            elif susp > 0.7:
                score += 1
                reasons.append(
                    f"PNG chunk anomaly ({img_name}) → {chunk_info}"
                )
            # mild anomalies = soft signal only
            else:
                score += 0.3
                reasons.append(
                    f"Possible PNG metadata irregularity ({img_name})"
                )

    # PDF streams
    pdf = findings.get("pdf_streams") or {}
    for s_stream in pdf.get("streams", []):
        if s_stream.get("entropy", 0) >= 7.8 or s_stream.get("magic_hit", False):
            score += 0.5
            tag = "magic" if s_stream.get("magic_hit") else "entropy"
            reasons.append(f"PDF object stream {tag} (obj#{s_stream.get('index')})")

    # DOCX
    doc = findings.get("docx") or {}
    for e in doc.get("embeds", []):
        if e.get("entropy", 0) >= 7.8 or e.get("suspicious_ext", False):
            score += 0.5
            reasons.append(
                f"DOCX embedded binary suspicious ({os.path.basename(e.get('name', 'embed'))})"
            )

    if doc.get("macros", {}).get("has_macros"):
        score += 0.5
        reasons.append("VBA Macros present")

    label = "LOW / CLEAN LIKELY"
    if score >= 3.0:
        label = "HIGH SUSPICION"
    elif score >= 2.0:
        label = "MEDIUM SUSPICION"

    return label, reasons


# ---------------------------------------------------------------------------
# Core scan
# ---------------------------------------------------------------------------

def run_scan(filepath: str, force_heuristic: bool = False) -> dict:
    console.print(Panel.fit(BANNER, border_style="green"))
    console.print(f"[bold cyan]Target:[/bold cyan] {filepath}")

    everything = extract_all(filepath)

    results = {
        "file": filepath,
        "images_results": [],
        "pdf_streams": None,
        "docx": None,
    }

    # --- image-level detectors ------------------------------------------------
    for img in track(
        everything.get("images", []),
        description="[bold yellow]Analyzing images[/bold yellow]",
    ):
        r1 = analyze_image(img)
        r2 = analyze_jpeg_dct(img)
        r3 = analyze_file_append(img)
        r4 = analyze_png_chunks(img)
        img_result = {
            "image": img,
            "lsb": r1,
            "dct": r2,
            "append": r3,
            "pngchunks": r4,
        }
        results["images_results"].append(img_result)

        pngchunks = img_result.get("pngchunks", {})
        if pngchunks.get("suspicion", 0) > 0.3 or pngchunks.get("findings"):
            payload_path, status = extract_zip_from_png(img_result["image"])
            img_result["payload"] = {"status": status, "path": payload_path}
            if payload_path:
                console.print(f"[bold green]→ Payload extracted:[/bold green] {payload_path}")
            else:
                console.print(f"[yellow]→ Extraction attempt: {status}[/yellow]")

    # --- PDF / DOCX detectors -------------------------------------------------
    if everything.get("is_pdf"):
        console.print("[magenta]* PDF object stream analysis[/magenta]")
        results["pdf_streams"] = analyze_pdf_streams(filepath)

    if everything.get("is_docx") or everything.get("is_doc"):
        console.print("[magenta]* DOCX/Doc embedded object & macro analysis[/magenta]")
        results["docx"] = analyze_docx_embeds(filepath)

    # --- numeric score --------------------------------------------------------
    numeric_score = compute_numeric_score(results)
    results["summary"] = results.get("summary", {}) or {}
    results["summary"]["numeric_score"] = numeric_score

    # --- hard evidence override ----------------------------------------------
    strong_evidence = False
    for im in results.get("images_results", []) or []:
        png = im.get("pngchunks", {}) or {}
        app = im.get("append", {}) or {}

        # PNG findings: e.g., "exe in chunk IDAT", "zip in chunk IDAT"
        for f_msg in (png.get("findings") or []):
            fl = str(f_msg).lower()
            if ("exe in chunk" in fl) or ("zip in chunk" in fl) or ("pdf in chunk" in fl):
                strong_evidence = True
                break
        if strong_evidence:
            break

        # Appended file findings (if detector provides them)
        for f_msg in (app.get("findings") or []):
            fl = str(f_msg).lower()
            if ("exe at offset" in fl) or ("zip at offset" in fl) or ("pdf at offset" in fl):
                strong_evidence = True
                break
        if strong_evidence:
            break

    # PDF-based strong evidence
    if not strong_evidence:
        pdf = results.get("pdf_streams") or {}
        for s_stream in pdf.get("streams", []) or []:
            if s_stream.get("magic_hit", False):
                strong_evidence = True
                break

    # DOCX-based strong evidence
    if not strong_evidence:
        doc = results.get("docx") or {}
        if doc:
            for e in doc.get("embeds", []) or []:
                name = str(e.get("name", "")).lower()
                susp_ext = bool(e.get("suspicious_ext", False))
                if susp_ext or name.endswith((".exe", ".dll", ".js", ".vbs", ".bat", ".ps1")):
                    strong_evidence = True
                    break
            if (not strong_evidence) and doc.get("macros", {}).get("has_macros"):
                strong_evidence = True

    results["summary"]["hard_evidence"] = strong_evidence

    # --- heuristic label + reasons -------------------------------------------
    label, reasons = classify(results)
    results["summary"]["heuristic_label"] = label
    results["summary"]["reasons"] = reasons

    # --- final decision logic -------------------------------------------------
    # 1) hard-evidence override
    # 2) numeric threshold (unless --heuristic)
    # 3) pure heuristic fallback
    if strong_evidence:
        final_label = "HIGH SUSPICION (forensic evidence)"
        results["summary"]["classification"] = final_label
        results["summary"]["threshold_used"] = OPT_THRESHOLD
    elif (not force_heuristic) and (OPT_THRESHOLD is not None):
        if numeric_score >= OPT_THRESHOLD:
            # severity band based on how far above threshold
            if numeric_score >= min(1.0, OPT_THRESHOLD + 0.3):
                final_label = "HIGH SUSPICION (threshold)"
            else:
                final_label = "MEDIUM SUSPICION (threshold)"
        else:
            final_label = "LOW / CLEAN LIKELY (threshold)"

        results["summary"]["classification"] = final_label
        results["summary"]["threshold_used"] = OPT_THRESHOLD
    else:
        results["summary"]["classification"] = label

    # friendly CLI print of score/threshold
    console.print(f"[blue]numeric_score={numeric_score:.3f}[/blue]")
    if OPT_THRESHOLD is not None:
        console.print(f"[blue]using_threshold={OPT_THRESHOLD}[/blue]")

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    global OPT_THRESHOLD

    parser = argparse.ArgumentParser(description="Steganography Detection Toolkit (CLI + JSON)")
    parser.add_argument("file", help="File to scan")
    parser.add_argument("--json", action="store_true", help="Save full JSON report")
    parser.add_argument(
        "--threshold",
        type=float,
        help="Override numeric_score threshold for this run "
             "(default: value from optimal_threshold.json or 0.2)",
    )
    parser.add_argument(
        "--heuristic",
        action="store_true",
        help="Force heuristic classification (ignore numeric threshold)",
    )
    args = parser.parse_args()

    if args.threshold is not None:
        thr_raw = float(args.threshold)
        if 0.0 <= thr_raw <= 1.0:
            OPT_THRESHOLD = thr_raw
        else:
            thr_clamped = max(0.0, min(1.0, thr_raw))
            console.print(
                f"[yellow]Warning:[/yellow] CLI threshold {thr_raw} outside [0,1]; "
                f"clamping to {thr_clamped}"
            )
            OPT_THRESHOLD = thr_clamped

    if not os.path.exists(args.file):
        console.print("[bold red]Error:[/bold red] File not found.")
        sys.exit(1)

    out = run_scan(args.file, force_heuristic=args.heuristic)

    # Pretty table
    table = Table(title="Scan Summary", show_header=True, header_style="bold cyan")
    table.add_column("File")
    table.add_column("Result", justify="center")
    table.add_column("Reasons (top)")
    reasons_preview = "; ".join(out["summary"]["reasons"][:3]) or "-"
    table.add_row(args.file, out["summary"]["classification"], reasons_preview)
    console.print(table)

    if args.json:
        path = save_report(args.file, out)
        console.print(f"[green]JSON report saved:[/green] {path}")


if __name__ == "__main__":
    main()
