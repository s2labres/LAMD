# LAMD

[![Paper](https://img.shields.io/badge/arXiv-2502.13055-b31b1b.svg)](https://arxiv.org/abs/2502.13055)
[![Dataset](https://img.shields.io/badge/Zenodo-10.5281%2Fzenodo.14884736-blue.svg)](https://doi.org/10.5281/zenodo.14884736)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

Official research implementation of **LAMD: Context-driven Android Malware
Detection and Classification with LLMs**.

## Quick start

Prerequisites:

- Python 3.10–3.12;
- [uv](https://docs.astral.sh/uv/) (recommended) or pip;
- Java 11+, Maven 3.8+, and Android SDK platforms for graph extraction;
- an OpenAI API key for LLM reasoning.

```bash
git clone https://github.com/s2labres/LAMD.git
cd LAMD

uv sync
cp .env.example .env
# Edit .env and set OPENAI_API_KEY.

./scripts/setup_slicer.sh
uv run lamd doctor --require-openai --require-slicer \
  --android-platforms "$ANDROID_HOME/platforms"
```

`setup_slicer.sh` compiles the versioned `java-slicer/` source. Maven
resolves the exact dependency versions declared in its `pom.xml`; the resulting
shaded JAR is `java-slicer/target/lamd-slicer.jar`.

### 1. Extract key context

Place authorized APKs in `data/apks/<SHA256>.apk`, then process one sample:

```bash
uv run lamd slice \
  --apk-dir data/apks \
  --output-dir data/graphs \
  --android-platforms "$ANDROID_HOME/platforms" \
  --sha256 <SHA256>
```

Or process a published split deterministically:

```bash
uv run lamd slice \
  --apk-dir data/apks \
  --output-dir data/graphs \
  --android-platforms "$ANDROID_HOME/platforms" \
  --split dataset/test_ood_lamd.txt
```

### 2. Run LAMD

Resume a split-level experiment:

```bash
uv run lamd analyze \
  --processed-dir data/graphs \
  --split dataset/test_ood_lamd.txt \
  --output-dir results/ood
```

The corresponding ablations are selected with:

```bash
--ablation no-verification  # LAMD-F
--ablation flat             # LAMD-R
```

### 3. Evaluate predictions

```bash
uv run lamd evaluate \
  --results-dir results/ood \
  --split dataset/test_ood_lamd.txt
```

## Repository layout

```text
.
├── src/lamd/                 maintained Python package
│   ├── pipeline.py           three-tier analysis and factual correction
│   ├── prompts.py            original-release prompt templates
│   ├── relations.py          five relation types and DRC
│   ├── slicer.py             Java slicer wrapper
│   ├── evaluation.py         F1/FPR/FNR computation
│   └── cli.py                `lamd` command
├── dataset/                  hashes, labels, and API catalogues
├── java-slicer/              FlowDroid/Soot context extractor
└── scripts/setup_slicer.sh   Java build and verification entry point
```

## Citation

```bibtex
@inproceedings{qian2025lamd,
  title={Lamd: Context-driven android malware detection and classification with llms},
  author={Qian, Xingzhi and Zheng, Xinran and He, Yiling and Yang, Shuo and Cavallaro, Lorenzo},
  booktitle={2025 IEEE Security and Privacy Workshops (SPW)},
  pages={126--136},
  year={2025},
  organization={IEEE}
}
```

## License

The maintained code in this repository is provided under Apache-2.0. Dataset,
APK, and dependency rights remain subject to their respective terms.
