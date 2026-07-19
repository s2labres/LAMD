# LAMD Java slicer

This Maven module contains the static-analysis component described in Sections
3.2 and Appendix D of the paper. It uses FlowDroid/Soot to build a call graph,
find invocations from the stable suspicious-API list, and perform a two-stage
backward slice over each invoking function. It emits:

```text
<output>/<apk-sha256>/<api-index>/<instance>/
├── CallGraph/*.dot
├── SliceGraph/*.dot
├── Relation/*.txt
├── cfg/*.dot
└── code/*.jimple
```

Build with Java 11+ and Maven 3.8+:

```bash
mvn --batch-mode --file java-slicer/pom.xml clean verify
```

The shaded executable is `java-slicer/target/lamd-slicer.jar`. Its seven
arguments are managed by `lamd slice`; direct invocation is:

```bash
java -jar java-slicer/target/lamd-slicer.jar \
  <apk> <output-dir> <android-sdk-platforms> <sensitive-api-list> \
  <k> <msdroid:true|false> <debug:true|false>
```

The slicer performs static analysis and never installs or executes the APK.
Nevertheless, process malware only inside an isolated, resource-limited
environment.
