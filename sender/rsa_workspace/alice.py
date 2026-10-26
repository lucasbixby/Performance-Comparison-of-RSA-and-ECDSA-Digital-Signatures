"""
    RSA SIGNATURE OPERATIONS:
    RSA signature generation involves hashing a document and encrypting the hash with the sender's
    private key. Verification decrypts the hash using the sender's public key and compares it against a newly
    computed hash of the received message.

    Task:
        -   Generate an RSA private key (2048-bit and 4096-bit)
        -   Inspect the private key structure (modulus, public exponent, private exponent, prime factors)
        -   Extract the corresponding public key and send it to Bob's folder (receiver/rsa_workspace)
        -   For each test file (1 MB, 10 MB, 100 MB): sign it, send file + signature to Bob,
            Bob verifies, and time both operations (Section 5 / Table 1)
        -   Save results to exercise_2/results/ and draw charts in exercise_2/charts/ (needs matplotlib)
"""

import csv, os, subprocess, shutil, statistics, time
from pathlib import Path

KEY_SIZES = [2048, 4096]
FAMILY = "RSA"
FILE_SIZES_MB = [1, 10, 100]
ITERATIONS = 10


def run(*args, cwd, show=True):
    r = subprocess.run(["openssl", *args], cwd=cwd, capture_output=True, text=True)
    if show:
        print(r.stdout or r.stderr)
    if r.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed:\n{r.stderr}")
    return r


def timed(*args, cwd):
    """One untimed warm-up, then ITERATIONS timed runs. Returns (mean, stdev) in milliseconds."""
    run(*args, cwd=cwd, show=False)
    samples = []
    for _ in range(ITERATIONS):
        t0 = time.perf_counter()
        run(*args, cwd=cwd, show=False)
        samples.append((time.perf_counter() - t0) * 1000)
    return statistics.mean(samples), statistics.stdev(samples)


sender = Path(__file__).resolve().parent
receiver = sender.parent.parent / "receiver" / "rsa_workspace"
receiver.mkdir(parents=True, exist_ok=True)


def make_test_files():
    """5.2: create file_1MB.bin, file_10MB.bin, file_100MB.bin (same as `dd if=/dev/urandom ...`)."""
    for mb in FILE_SIZES_MB:
        f = sender / f"file_{mb}MB.bin"
        if not f.exists() or f.stat().st_size != mb * 1024 * 1024:
            print(f"Creating {f.name} ...")
            with open(f, "wb") as out:
                for _ in range(mb):
                    out.write(os.urandom(1024 * 1024))


def generate_keys(bits):
    """3.1: Alice generates her key pair and sends the public key to Bob."""
    priv, pub = f"privateKeyA_rsa{bits}.pem", f"publicKeyA_rsa{bits}.pem"
    print(f"=== {bits}-bit key ===")
    run("genrsa", "-out", priv, str(bits), cwd=sender, show=False)
    run("rsa", "-in", priv, "-text", "-noout", cwd=sender)
    run("rsa", "-in", priv, "-pubout", "-out", pub, cwd=sender, show=False)
    shutil.copy(sender / pub, receiver)
    return priv, pub


def execute_tests(binary_file, priv, pub, bits):
    """3.2 + 3.3 for one file: sign, send to Bob, verify, and time both steps."""
    sig = f"rsa{bits}_signature_{Path(binary_file).stem}.bin"

    # 3.2  Alice signs the file and sends file + signature to Bob
    sign_ms, sign_sd = timed("dgst", "-sha256", "-sign", priv, "-out", sig, binary_file, cwd=sender)
    shutil.copy(sender / binary_file, receiver)
    shutil.copy(sender / sig, receiver)

    # 3.3  Bob verifies with Alice's public key
    result = run("dgst", "-sha256", "-verify", pub, "-signature", sig, binary_file, cwd=receiver, show=False)
    print(f"{bits}-bit, {binary_file}: {result.stdout.strip()}")
    if "Verified OK" not in result.stdout:
        raise RuntimeError(f"Verification failed for {binary_file}")
    verify_ms, verify_sd = timed("dgst", "-sha256", "-verify", pub, "-signature", sig, binary_file, cwd=receiver)

    sig_bytes = (sender / sig).stat().st_size
    return sign_ms, sign_sd, verify_ms, verify_sd, sig_bytes


EXERCISE = sender.parent.parent
RESULTS_DIR = EXERCISE / "results"
CHARTS_DIR = EXERCISE / "charts"
FIELDS = ["family", "key", "file_mb", "sign_ms", "sign_sd", "verify_ms", "verify_sd", "sig_bytes"]


def save_results(rows):
    RESULTS_DIR.mkdir(exist_ok=True)
    path = RESULTS_DIR / f"{FAMILY.lower()}_results.csv"
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(rows)
    print(f"Saved {path.relative_to(EXERCISE)}")


def load_results(family):
    path = RESULTS_DIR / f"{family.lower()}_results.csv"
    if not path.exists():
        return None
    with open(path, newline="") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["file_mb"] = int(r["file_mb"])
        for k in ("sign_ms", "sign_sd", "verify_ms", "verify_sd"):
            r[k] = float(r[k])
        r["sig_bytes"] = int(r["sig_bytes"])
    return rows


def make_charts(rows):
    try:
        import matplotlib
        matplotlib.use("Agg")                 
        import matplotlib.pyplot as plt
    except ImportError:
        print("matplotlib is not installed, so no charts were made. Run:  pip install matplotlib")
        return
    CHARTS_DIR.mkdir(exist_ok=True)
    sizes = [f"{mb} MB" for mb in FILE_SIZES_MB]
    keys = list(dict.fromkeys(r["key"] for r in rows))
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]

    
    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    for i, key in enumerate(keys):
        rs = [r for r in rows if r["key"] == key]
        c = colors[i % len(colors)]
        ax.errorbar(sizes, [r["sign_ms"] for r in rs], yerr=[r["sign_sd"] for r in rs],
                    marker="o", color=c, capsize=3, label=f"{key} sign")
        ax.errorbar(sizes, [r["verify_ms"] for r in rs], yerr=[r["verify_sd"] for r in rs],
                    marker="s", linestyle="--", color=c, capsize=3, label=f"{key} verify")
    ax.set_title(f"{FAMILY}: signing vs. verifying (mean of {ITERATIONS} runs, ±1 SD)")
    ax.set_xlabel("File size")
    ax.set_ylabel("Time (ms)")
    ax.grid(alpha=0.3)
    ax.legend()
    fig.tight_layout()
    name = "a_rsa_sign_vs_verify.png" if FAMILY == "RSA" else "b_ecdsa_sign_vs_verify.png"
    fig.savefig(CHARTS_DIR / name, dpi=150)
    plt.close(fig)
    print(f"Saved charts/{name}")

    
    other = load_results("ECDSA" if FAMILY == "RSA" else "RSA")
    if other is None:
        print("Run the other workspace's alice.py too to get the RSA vs. ECDSA comparison charts.")
        return
    both = (rows + other) if FAMILY == "RSA" else (other + rows)
    all_keys = list(dict.fromkeys(f"{r['family']} {r['key']}" for r in both))
    width = 0.8 / len(all_keys)

    
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.6))
    for ax, metric, title in [(axes[0], "sign", "Signing"), (axes[1], "verify", "Verification")]:
        for i, key in enumerate(all_keys):
            rs = [next(r for r in both if f"{r['family']} {r['key']}" == key and r["file_mb"] == mb)
                  for mb in FILE_SIZES_MB]
            ax.bar([x + i * width for x in range(len(sizes))], [r[f"{metric}_ms"] for r in rs], width,
                   yerr=[r[f"{metric}_sd"] for r in rs], capsize=2, label=key, color=colors[i % len(colors)])
        ax.set_xticks([x + width * (len(all_keys) - 1) / 2 for x in range(len(sizes))], sizes)
        ax.set_title(f"RSA vs. ECDSA: {title}")
        ax.set_xlabel("File size")
        ax.set_ylabel("Time (ms)")
        ax.grid(axis="y", alpha=0.3)
    axes[0].legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(CHARTS_DIR / "c_rsa_vs_ecdsa_timing.png", dpi=150)
    plt.close(fig)
    print("Saved charts/c_rsa_vs_ecdsa_timing.png")

    
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    sig_sizes = [max(r["sig_bytes"] for r in both if f"{r['family']} {r['key']}" == key) for key in all_keys]
    bars = ax.bar(all_keys, sig_sizes, color=[colors[i % len(colors)] for i in range(len(all_keys))])
    ax.bar_label(bars, labels=[f"{b} B" for b in sig_sizes], padding=2)
    ax.set_ylim(0, max(sig_sizes) * 1.12)
    ax.set_title("Signature size by algorithm")
    ax.set_ylabel("Bytes")
    ax.grid(axis="y", alpha=0.3)
    ax.tick_params(axis="x", labelsize=8)
    fig.tight_layout()
    fig.savefig(CHARTS_DIR / "d_signature_sizes.png", dpi=150)
    plt.close(fig)
    print("Saved charts/d_signature_sizes.png")


def main():
    make_test_files()
    results = []
    for bits in KEY_SIZES:
        priv, pub = generate_keys(bits)
        for mb in FILE_SIZES_MB:
            sign_ms, sign_sd, verify_ms, verify_sd, sig_bytes = execute_tests(f"file_{mb}MB.bin", priv, pub, bits)
            results.append(dict(family=FAMILY, key=f"{bits}-bit", file_mb=mb, sign_ms=sign_ms, sign_sd=sign_sd,
                                verify_ms=verify_ms, verify_sd=verify_sd, sig_bytes=sig_bytes))

    print(f"\nTable 1: RSA Signature Generation & Verification Timing (mean of {ITERATIONS} runs)")
    print(f"{'RSA Key Size':<14}{'File Size':<11}{'Sign Time (ms)':>16}{'Verify Time (ms)':>18}{'Sig Size (Bytes)':>18}")
    print("-" * 77)
    for r in results:
        print(f"{r['key']:<14}{str(r['file_mb']) + ' MB':<11}{r['sign_ms']:>16.2f}{r['verify_ms']:>18.2f}{r['sig_bytes']:>18}")

    print()
    save_results(results)
    make_charts(results)


if __name__ == "__main__":
    main()