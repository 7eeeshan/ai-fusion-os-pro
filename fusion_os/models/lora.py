"""Local LoRA training of the engine's model on the person's rated chats.

Steps, each started by the person from the Improve page (each shows its download size first):
1. Trainer runtime (~3 GB): a private copy of the app's Python plus pinned torch (CUDA 12.1), transformers, peft,
   accelerate and bitsandbytes, installed into <data>/trainer. pip comes from a hash-checked wheel; the llama.cpp
   converter comes from the hash-checked llama-cpp-python source release on PyPI (only its Python scripts are used).
2. Base weights (~15 GB for a 7B model): the Hugging Face original of the GGUF model the engine runs (QLoRA needs
   the unquantized weights; the GGUF stays what the engine serves).
3. Training: the engine pauses its local models to free the GPU, `lora_train.py` trains a QLoRA adapter on the
   training set (local answers rated up and better answers the person wrote), measures held-out loss before and
   after, converts the adapter to GGUF, and the engine resumes.
4. Deploy: only if the person chooses; the engine loads the model with the adapter (--lora-scaled). Roll back at
   any time, which restores the plain model.
Nothing here runs automatically, and nothing leaves this PC except the downloads in steps 1 and 2.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional

PIP_WHEEL = ("https://files.pythonhosted.org/packages/ef/7d/500c9ad20238fcfcb4cb9243eede163594d7020ce87bd9610c9e02771876/"
             "pip-24.3.1-py3-none-any.whl", "3790624780082365f47549d032f3770eeb2b1e8bd1f7b2e02dace1afa361b4ed")
CONVERTER_SDIST = ("https://files.pythonhosted.org/packages/source/l/llama_cpp_python/llama_cpp_python-0.3.38.tar.gz",
                   "0570c9736b5e2a239b651da18687238eeba7fc2369dcdfd8cbb009dc1321e23f")
TORCH = ["torch==2.5.1"]
TORCH_INDEX = "https://download.pytorch.org/whl/cu121"  # CUDA 12.1 wheels: RTX 20xx (sm_75) and newer
PACKAGES = ["transformers==4.46.3", "peft==0.13.2", "accelerate==1.1.1", "bitsandbytes==0.45.0",
            "huggingface_hub==0.26.2", "safetensors==0.4.5", "sentencepiece==0.2.0", "numpy==2.1.3",
            "pyyaml==6.0.2", "tqdm==4.67.1", "protobuf==5.28.3"]
RUNTIME_GB, MIN_EXAMPLES = 3.2, 20
# GGUF file names -> the Hugging Face original. Others: set the repo on the Improve page.
KNOWN_BASES = [
    (r"qwen2\.5-7b", "Qwen/Qwen2.5-7B-Instruct", 15.2), (r"qwen2\.5-3b", "Qwen/Qwen2.5-3B-Instruct", 6.2),
    (r"qwen2\.5-1\.5b", "Qwen/Qwen2.5-1.5B-Instruct", 3.1), (r"qwen2\.5-coder-7b", "Qwen/Qwen2.5-Coder-7B-Instruct", 15.2),
    (r"llama-?3\.1-8b", "meta-llama/Llama-3.1-8B-Instruct", 16.1), (r"llama-?3\.2-3b", "meta-llama/Llama-3.2-3B-Instruct", 6.4),
    (r"mistral-7b", "mistralai/Mistral-7B-Instruct-v0.3", 14.5), (r"gemma-2-9b", "google/gemma-2-9b-it", 18.5),
    (r"phi-?3\.5-mini", "microsoft/Phi-3.5-mini-instruct", 7.6),
]
SCRIPT = Path(__file__).with_name("lora_train.py")


def guess_base(model: str) -> Optional[tuple[str, float]]:
    name = model.split("/")[-1].lower()
    for rx, repo, gb in KNOWN_BASES:
        if re.search(rx, name):
            return repo, gb
    return None


def _download(url: str, sha256: str, dst: Path) -> Path:
    dst.parent.mkdir(parents=True, exist_ok=True)
    tmp = dst.with_suffix(dst.suffix + ".part")
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=60) as r, open(tmp, "wb") as fh:  # noqa: S310 (pinned https URL)
        while chunk := r.read(1 << 20):
            h.update(chunk)
            fh.write(chunk)
    if h.hexdigest() != sha256:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"download of {url.rsplit('/', 1)[-1]} failed its SHA-256 check")
    tmp.replace(dst)
    return dst


def _no_window() -> dict:
    return {"creationflags": 0x0800_0000} if os.name == "nt" else {}


class LoraTrainer:
    def __init__(self, home: Path, engine, lessons, env: Optional[dict] = None):
        self.root = home / "trainer"
        self.engine, self.lessons = engine, lessons
        self.env = dict(os.environ if env is None else env)
        self.state_file = self.root / "state.json"
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self.root.mkdir(parents=True, exist_ok=True)
        st = self.state()
        if st.get("task") and st.get("running"):  # the app was closed mid-task
            st.update(running=False, error="stopped when the app closed; start it again")
            self._save(st)
            self._resume_engine()

    # ---------- state ----------
    def state(self) -> dict:
        try:
            return json.loads(self.state_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _save(self, st: dict) -> None:
        tmp = self.state_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=1), encoding="utf-8")
        tmp.replace(self.state_file)

    def _update(self, **kw) -> dict:
        with self._lock:
            st = self.state()
            st.update(kw)
            self._save(st)
            return st

    def _log(self, line: str) -> None:
        with open(self.root / "trainer.log", "a", encoding="utf-8") as fh:
            fh.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line.rstrip()[:4000] + "\n")

    # ---------- paths ----------
    @property
    def python(self) -> Path:
        return self.root / "python" / ("python.exe" if os.name == "nt" else "bin/python")

    def base_dir(self, repo: str) -> Path:
        return self.root / "base" / repo.replace("/", "__")

    @property
    def converter(self) -> Path:
        return self.root / "converter"

    def runtime_ready(self) -> bool:
        return self.python.exists() and (self.root / "runtime.json").exists() and \
            (self.converter / "convert_lora_to_gguf.py").exists()

    # ---------- status ----------
    def engine_model(self) -> Optional[str]:
        try:
            ids = [m["id"] for m in self.engine.models() if m.get("id")]
        except Exception:
            return None
        want = self.env.get("FUSION_OS_ENGINE_MODEL")
        if want and want in ids:
            return want
        local = [i for i in ids if i.startswith("llamacpp/")]
        return (local or [None])[0]

    def adapters(self) -> dict:
        try:
            r = self.engine.client.get(f"{self.engine.base_url}/api/adapters", headers=self.engine._headers(),
                                       timeout=10)
            return r.json() if r.status_code < 400 else {}
        except Exception:
            return {}

    def status(self) -> dict:
        st = self.state()
        model = self.engine_model()
        base = (st.get("base_repo") and (st["base_repo"], st.get("base_gb", 0))) or (guess_base(model) if model else None)
        stats = self.lessons.stats() if self.lessons else {}
        return {
            "model": model, "base_repo": base[0] if base else None, "base_gb": base[1] if base else None,
            "base_ready": bool(base and (self.base_dir(base[0]) / "config.json").exists()),
            "runtime_ready": self.runtime_ready(), "runtime_gb": RUNTIME_GB,
            "examples": stats.get("training_examples", 0), "min_examples": MIN_EXAMPLES,
            "task": st.get("task"), "running": bool(st.get("running")), "progress": st.get("progress"),
            "error": st.get("error"), "jobs": st.get("jobs", [])[-10:], "deployed": self.adapters().get("adapters", {}),
            "gpu_note": "On a 6 GB GPU a 7B model trains with part of it in RAM: expect hours per run.",
        }

    # ---------- background tasks ----------
    def _start(self, task: str, fn) -> dict:
        with self._lock:
            if self._thread and self._thread.is_alive():
                raise RuntimeError(f"busy: {self.state().get('task')}")
            st = self.state()
            st.update(task=task, running=True, error=None, progress=None)
            self._save(st)

            def run():
                try:
                    fn()
                    self._update(running=False)
                except Exception as exc:
                    self._log(f"{task} failed: {exc}")
                    self._update(running=False, error=str(exc)[:1000])
            self._thread = threading.Thread(target=run, daemon=True, name=f"lora-{task}")
            self._thread.start()
        return self.state()

    def _run(self, argv: list, label: str, env: Optional[dict] = None, on_line=None, timeout: float = 4 * 3600) -> None:
        self._log(f"{label}: {' '.join(str(a) for a in argv)[:600]}")
        p = subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace", env=env or self._env(), cwd=str(self.root),
                             stdin=subprocess.DEVNULL, **_no_window())
        t0 = time.monotonic()
        assert p.stdout is not None
        for line in p.stdout:
            self._log(line)
            if on_line:
                on_line(line)
            if time.monotonic() - t0 > timeout:
                p.kill()
                raise RuntimeError(f"{label} took too long")
        if p.wait() != 0:
            raise RuntimeError(f"{label} failed (exit {p.returncode}); see {self.root / 'trainer.log'}")

    def _env(self) -> dict:
        env = {k: v for k, v in self.env.items() if not k.startswith(("PYTHON", "PIP_"))}
        env.update(PYTHONNOUSERSITE="1", PYTHONUTF8="1", HF_HUB_DISABLE_TELEMETRY="1",
                   HF_HOME=str(self.root / "hf-cache"), PIP_DISABLE_PIP_VERSION_CHECK="1")
        return env

    # 1. runtime
    def setup_runtime(self) -> dict:
        return self._start("runtime", self._setup_runtime)

    def _setup_runtime(self) -> None:
        py_dir = self.root / "python"
        if not self.python.exists():
            self._update(progress="copying Python")
            if os.name == "nt":  # the app's embedded Python, copied so the app's own stays untouched
                src = Path(sys.executable).parent
                shutil.copytree(src, py_dir, dirs_exist_ok=True,
                                ignore=shutil.ignore_patterns("Lib", "__pycache__", "*.pyc"))
                for pth in py_dir.glob("python*._pth"):
                    pth.write_text("\n".join([f"{pth.stem}.zip", ".", "Lib\\site-packages", "import site"]) + "\n",
                                   encoding="ascii")
                (py_dir / "Lib" / "site-packages").mkdir(parents=True, exist_ok=True)
            else:
                self._run([sys.executable, "-m", "venv", py_dir], "venv")
        pip = _download(*PIP_WHEEL, self.root / "downloads" / "pip-24.3.1-py3-none-any.whl")
        base = [self.python, str(pip) + "/pip", "install", "--no-input", "--prefer-binary"]
        if os.name == "nt":
            base += ["--target", str(py_dir / "Lib" / "site-packages"), "--upgrade"]
        self._update(progress="installing torch (about 2.5 GB)")
        self._run(base + ["--index-url", TORCH_INDEX] + TORCH, "torch")
        self._update(progress="installing transformers, peft, bitsandbytes")
        self._run(base + PACKAGES, "packages")
        self._update(progress="getting the llama.cpp adapter converter")
        sdist = _download(*CONVERTER_SDIST, self.root / "downloads" / "llama_cpp_python-0.3.38.tar.gz")
        self._extract_converter(sdist)
        (self.root / "runtime.json").write_text(json.dumps({"torch": TORCH, "packages": PACKAGES,
                                                            "converter": CONVERTER_SDIST[1], "at": time.time()}))
        self._update(progress="trainer ready")

    def _extract_converter(self, sdist: Path) -> None:
        dst = self.converter
        shutil.rmtree(dst, ignore_errors=True)
        dst.mkdir(parents=True)
        want = re.compile(r"^llama_cpp_python-[^/]+/vendor/llama\.cpp/(convert_lora_to_gguf\.py|convert_hf_to_gguf\.py|"
                          r"gguf-py/gguf/.+|conversion/.+)$")
        with tarfile.open(sdist, "r:gz") as tf:
            for m in tf.getmembers():
                mm = want.match(m.name)
                if not mm or not m.isfile():
                    continue
                rel = Path(mm.group(1))
                if rel.is_absolute() or ".." in rel.parts:
                    continue
                out = dst / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                with tf.extractfile(m) as src, open(out, "wb") as fh:  # type: ignore[union-attr]
                    shutil.copyfileobj(src, fh)

    # 2. base weights
    def download_base(self, repo: Optional[str] = None) -> dict:
        model = self.engine_model()
        guess = guess_base(model) if model else None
        repo = repo or (guess[0] if guess else None)
        if not repo or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
            raise RuntimeError("which Hugging Face model is the engine's model based on? Set the repo first")
        if not self.runtime_ready():
            raise RuntimeError("set up the trainer first")
        self._update(base_repo=repo, base_gb=(guess[1] if guess and guess[0] == repo else None))

        def go():
            self._update(progress=f"downloading {repo}")
            code = ("import sys; from huggingface_hub import snapshot_download; snapshot_download(sys.argv[1], "
                    "local_dir=sys.argv[2], allow_patterns=['*.json', '*.safetensors', '*.model', '*.txt', "
                    "'tokenizer*', '*.jinja'])")
            self._run([self.python, "-I", "-c", code, repo, self.base_dir(repo)], "download base", timeout=12 * 3600)
            self._update(progress="base weights ready")
        return self._start("base", go)

    # 3. training
    def train(self, epochs: float = 2, gpu_mem_gb: float = 0) -> dict:
        st = self.status()
        if not st["runtime_ready"] or not st["base_ready"]:
            raise RuntimeError("set up the trainer and download the base weights first")
        if st["examples"] < MIN_EXAMPLES:
            raise RuntimeError(f"rate more answers first: {st['examples']} of {MIN_EXAMPLES} training examples")
        model, repo = st["model"], st["base_repo"]
        job = time.strftime("job-%Y%m%d-%H%M%S")
        jdir = self.root / "jobs" / job
        jdir.mkdir(parents=True, exist_ok=True)
        n = self.lessons.export_jsonl(jdir / "dataset.jsonl")

        def go():
            self._pause_engine()
            try:
                last: dict = {}

                def on_line(line: str):
                    try:
                        ev = json.loads(line)
                    except ValueError:
                        return
                    last.update(ev)
                    if ev.get("event") == "step":
                        self._update(progress=f"training step {ev['step']} of {ev['of']}, loss {ev['loss']}, "
                                              f"about {round(ev.get('eta_s', 0) / 60)} min left")
                    elif ev.get("event") == "eval":
                        self._update(progress=f"measuring ({ev['stage']} loss {ev['loss']})")
                argv = [self.python, "-I", SCRIPT, "--base", self.base_dir(repo), "--data", jdir / "dataset.jsonl",
                        "--out", jdir / "adapter", "--epochs", epochs]
                if gpu_mem_gb:
                    argv += ["--gpu-mem-gb", gpu_mem_gb]
                self._run(argv, "train", on_line=on_line, timeout=24 * 3600)
            finally:
                self._resume_engine()
            self._update(progress="converting the adapter for llama.cpp")
            # The embedded Python ignores PYTHONPATH, so put the converter and its own gguf package on the path here.
            conv = ("import runpy, sys; d = sys.argv[1]; sys.path[:0] = [d, d + '/gguf-py']; "
                    "sys.argv = [d + '/convert_lora_to_gguf.py'] + sys.argv[2:]; "
                    "runpy.run_path(sys.argv[0], run_name='__main__')")
            self._run([self.python, "-I", "-c", conv, self.converter, "--base", self.base_dir(repo),
                       "--outfile", jdir / "adapter.gguf", "--outtype", "f16", jdir / "adapter"], "convert")
            info = json.loads((jdir / "adapter" / "training.json").read_text(encoding="utf-8"))
            better = info["trained_loss"] < info["base_loss"] * 0.98
            rec = {"id": job, "model": model, "examples": n, "base_loss": round(info["base_loss"], 4),
                   "trained_loss": round(info["trained_loss"], 4), "better": better, "at": time.time(),
                   "path": str(jdir / "adapter.gguf"), "minutes": round(info.get("seconds", 0) / 60)}
            st2 = self.state()
            st2.setdefault("jobs", []).append(rec)
            st2.update(progress=("done: the adapter improved held-out loss" if better else
                                 "done: no clear improvement, so deploying it is not recommended"))
            with self._lock:
                self._save(st2)
        return self._start("train", go)

    def _pause_engine(self) -> None:
        try:
            self.engine.client.post(f"{self.engine.base_url}/api/pause", headers=self.engine._headers(),
                                    json={"reason": "LoRA training in AI Fusion OS Pro"}, timeout=60)
        except Exception as exc:
            self._log(f"could not pause the engine: {exc}")

    def _resume_engine(self) -> None:
        try:
            self.engine.client.delete(f"{self.engine.base_url}/api/pause", headers=self.engine._headers(), timeout=30)
        except Exception:
            pass

    # 4. deploy / roll back
    def deploy(self, job_id: str, scale: float = 1.0) -> dict:
        job = next((j for j in self.state().get("jobs", []) if j["id"] == job_id), None)
        if not job or not Path(job["path"]).is_file():
            raise RuntimeError("no such trained adapter")
        name = job["model"].split("/", 1)[-1]
        r = self.engine.client.post(f"{self.engine.base_url}/api/adapters", headers=self.engine._headers(),
                                    json={"model": name, "path": job["path"], "scale": scale}, timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"the engine refused the adapter: {r.text[:300]}")
        self._update(deployed=job_id)
        return {"deployed": job_id, "model": job["model"]}

    def rollback(self, model: Optional[str] = None) -> dict:
        model = model or self.engine_model()
        if not model:
            raise RuntimeError("no engine model")
        r = self.engine.client.delete(f"{self.engine.base_url}/api/adapters/{model.split('/', 1)[-1]}",
                                      headers=self.engine._headers(), timeout=60)
        if r.status_code >= 400:
            raise RuntimeError(f"the engine could not remove the adapter: {r.text[:300]}")
        self._update(deployed=None)
        return {"rolled_back": model}
