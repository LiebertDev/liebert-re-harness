# External review of `main` — 2026-10-06

**Status: UNVERIFIED THIRD-PARTY REVIEW.** This file is a verbatim record of an
external model's review of commit `e3a928e4ea0306d636cdad65d7f9626a26c765c3`.
It is kept for traceability, not as a statement of fact about this repository.
Individual claims are being checked against the source; nothing here should be
cited as a repository fact until a verification pass has confirmed it.

**One edit was made to the original text:** upstream-only identifiers the
review quoted are replaced with `<REDACTED>`, because this repository does not
carry private-tree identifiers in new files (`test_no_private_tree_identifiers_in_public_package`).
The substance of the finding they belong to, number 27, is unchanged.

Reviewed commit: `e3a928e4ea0306d636cdad65d7f9626a26c765c3` (5 October 2026).
Language of the original: Turkish, kept as written.

---

## Verification pass — 2026-10-06

Every numbered finding below was checked against the source at the same commit
by two independent read-only audits (1-26 and 27-50), each required to cite a
real `path:line` or a command, and to write `DOĞRULANMADI` for anything it
could not measure. Result: **most findings hold**. The exceptions are recorded
here so no reader takes a wrong claim from this file.

`KISMEN` (partly right): **4, 7, 9, 23, 30, 40, 43, 45, 49**. Everything else
in 1-50 verified as stated, except where listed as a measurement error below.

### Measurement errors in this review

- **Every line count is exactly one too high.** Real (`wc -l`): `ida.py` 4037,
  `rizin.py` 2578, `vb6_pcode.py` 1776, `cpp_rtti.py` 1761, `binary.py` 1514,
  `frida_trace_client.py` 1337, `evidence/index.py` 1193, `msf_pdb.py` 995.
  Findings 5, 23 and 30 all carry the `+1` bias.
- **Finding 45:** there are **101** `tests/test_*.py` files, not "about 105".
- **Finding 43:** the "imports resolved at runtime" sentence is in
  `docs/CAPABILITIES_AND_LIMITS.md` only; it is not in `docs/ROADMAP.md`.
- **Finding 49:** the `crypto 7/4` figure it cites lives in
  `liebert_re/report/tool_families.py`, not in `docs/CAPABILITIES_AND_LIMITS.md`,
  which states no family ratio at all. The kernel drift it reports was real.
- **Finding 37:** names 2 undeclared imports; there are **7** (`UnityPy`,
  `androguard`, `dpkt`, `py7zr`, `rarfile`, `backports.zstd`, `loguru`). It also
  presents them as undisclosed, but `docs/INSTALL.md` and `README.md` already
  disclose the set and the wrong-shaped errors. The contract defect is real;
  the concealment is not.
- **Finding 4:** right that `ida_query` was wrongly denied, wrong to treat the
  whole sentence as drift — `ghidra_query` and `ilspy` genuinely have no
  implementation. The headline "this package has no native x86/x64 decompiler"
  is **true**: the pseudocode operation needs a separately licensed IDA.
- **Finding 7:** not an undisclaimed overclaim. `README.md` already says
  normalisation across engines is "Not here"; the tension is internal to README.
- **Finding 9:** the package does not merely default to `idat -A` —
  `liebert_re/tools/ida.py` already argues the case against in-process `idalib`
  (a crash in the analysis kernel takes down `idat`, not the harness). A
  separate measurement outside this repository recorded `idalib` blocking for
  260 s on a 25 MB PE with 59078 functions. The suggestion is already decided
  against, on crash-isolation and latency grounds, not licensing.
- **Finding 31:** the "481 findings / 469 one-line style" figures are quoted
  from this repository's own `pyproject.toml` comment, not independently
  measured by the reviewer.
- **Finding 48:** correct that the two test counts disagree, but
  `docs/BENCHMARKS.md` declares them unreconciled itself.
- **Finding 13:** the family is 6 named / 1 defined; the prose says "0/5". The
  two denominators are inconsistent.
- **Finding 1:** the capability table is accurate for every row it lists, but
  silently omits `game-engine 11/9`, `structured 3/2` and `web 2/2`.

### External-product claims, not repository facts

Findings 8, 9, 12, 14, 38 rest on vendor behaviour that cannot be measured from
this repository. Checked separately against current vendor sources on
2026-10-06: Ghidra's `DecompInterface` and in-tree PyGhidra (finding 8) and
angr's `CFGFast`/`CFGEmulated` (finding 14) are current and support the
suggestion. Two are based on an outdated premise: **FLOSS** (finding 38) has had
no stable release since v3.1.1 in September 2024, development moved to a
separate beta tool, and it publishes no documented Python library API — so any
integration is subprocess plus its JSON output, not an import. And the
`unicorn<3` upper bound suggested in finding 35 protects against nothing:
**Unicorn 3.x has never been released** (latest 2.1.4, September 2025). The
`capstone<6` half of that finding is sound — Capstone 6 publishes a breaking
change list. A further point the review missed: angr pins `capstone==5.0.9`
and `unicorn==2.1.4` exactly, so it cannot share an environment whose
capstone range is chosen independently.

### Acted on

Findings 1 and 49 are fixed in the same change that adds this section. Finding 4's
prompts were corrected before the scaffolding was untracked, so it no longer
applies to the published repository and cannot be checked from it. The
docstring-table drift is machine-checked: `tests/test_repo_discipline.py` asserts
the `tool_families.py` docstring table equals the live computed report.
`tests/test_docs_do_not_deny_shipped_tools.py` scans `README.md` and
`docs/CAPABILITIES_AND_LIMITS.md` only.

Note, 2026-10-06 (later the same day): an earlier version of this section said
that test also scanned `.claude/agents/`. That scanning was removed when the
multi-agent scaffolding was untracked. The agent prompts are development
scaffolding kept out of the repository, so their drift risk left with them and
is no longer machine-checked here.

The remaining findings are unactioned at the time of writing.

---

Bu sefer sadece IDA/kernel kısmına değil, **mevcut `main` branch'in tamamına** baktım: source tree, tool family/routing, IDA-Ghidra-Rizin katmanları, kernel/dynamic/emulation, Analysis IR, evidence/provenance, `.claude` agent'ları, CLI, dependency yapısı, CI/test stratejisi ve ROADMAP/README tutarlılığı dahil.

İncelediğim sürüm `main` üzerindeki **`e3a928e4ea0306d636cdad65d7f9626a26c765c3`**, 5 Ekim 2026 commit'i. En son `main` CI çalışması da başarılı.

## Genel sonuç

Projeyi iki farklı şekilde değerlendirmek gerekiyor.

**"RE tool library / open core" olarak:** yaklaşık **7/10**. Burada gerçekten iyi iş var. IDA wrapper ciddi, Rizin katmanı geniş, evidence mantığı düşünülmüş, hata durumlarının `"UNKNOWN"` / `TOOL_MISSING` olarak açıkça taşınması iyi, test sayısı yüksek ve subprocess izolasyonuna özen gösterilmiş.

**"AI'ın baştan sona otonom reverse-engineering yaptığı standalone harness" olarak:** yaklaşık **4/10**. Çünkü parçalar mevcut fakat onları bir analysis session'a dönüştüren asıl omurga public repoda yok.

En önemli teşhis şu:

```text
Sorun artık "yeterince tool yok" değil.

Sorun:
tool -> routing -> normalized IR -> evidence -> planner -> agent
zincirinin tamamlanmamış olması.
```

README de aslında worker dispatch, task queue ve session state gibi orchestration parçalarının private tree'de kaldığını açıkça söylüyor.

---

# 1. Capability manifest ile gerçek kod ciddi biçimde ayrışmış

`tool_families.py`'nin kullandığı kendi tanımını baz alarak mevcut kaynakta yeniden hesapladım.

Toplam **230 benzersiz declared tool adı** bulunuyor.

Bunların **127 tanesi gerçekten top-level implementation olarak mevcut**, **103 tanesi ise yalnız routing/roadmap/upstream adı**.

Bu "103 bug var" anlamına gelmiyor; bir kısmı bilinçli şekilde private tree'e ait. Ama standalone public harness açısından 103 capability boşluğu demek.

Daha da önemlisi, dosyanın kendi docstring'indeki sayılar şimdiden eskimiş. Orada `windows-kernel = 15 / 2` yazıyor.

Mevcut kaynakta gerçekte **`windows-kernel = 15 / 6`**, çünkü artık şunlar bulunuyor:

```text
kernel_triage
driver_major_function_scan
rip_relative_iat_scan
kernel_callback_registrations
ioctl_control_code_decode
tool_missing
```

Aynı şekilde `crypto` dokümanda `7/4`, mevcut kodda **`7/5`**, çünkü `api_hash_recover` eklenmiş.

Yani capability registry'nin kendisini açıklayan dokümantasyon bile canlı kodu takip etmiyor.

### Mevcut capability kapsaması

| Aile | Gerçek / Tanımlı | Durum |
|---|---:|---|
| binary | 4/4 | İyi |
| archive | 2/2 | İyi |
| android | 6/6 | Yüzey mevcut |
| network | 3/3 | İyi |
| database | 2/2 | İyi |
| JVM | 5/5 | İyi |
| webassembly | 2/2 | İyi |
| native | **57/80** | Geniş ama merkezi parçalar eksik |
| windows-kernel | **6/15** | Yetersiz |
| dotnet | **4/9** | Yarım |
| correlation | **5/18** | Çok eksik |
| dynamic | **8/39** | Çok eksik |
| identity | **4/14** | Orchestration eksikliği görülüyor |
| source | **3/7** | Yarım |
| debug | **6/9** | WinDbg tarafı yok |
| crypto | **5/7** | İyiye yakın |
| emulation | **1/6** | Fiilen yok; mevcut 1 tool `tool_missing` |
| workspace | 10/15 | RAG parçaları eksik |

Özellikle `correlation`, `dynamic`, `identity` ve `emulation` oranları standalone harness'in niye eksik hissettirdiğini açıklıyor.

---

# 2. Public repoda gerçek harness orchestration yok — P0

Bu benim en büyük bulgum.

`ARCHITECTURE_NOTES.md` açıkça private tree'de kalanları sayıyor:

```text
agent brain / model-dispatch loop
tool bus
deterministic planner
provider abstraction
worker dispatch
task queues
session bookkeeping
```

Public repoda bunların hiçbiri yok.

Dolayısıyla mevcut repo `AI -> planner -> tool bus -> execution state -> tools` değil; daha çok `tools + CLI + evidence utilities + agent promptları` şeklinde.

Bu bilinçli bir public/private ayrımı olabilir; fakat hedefiniz gerçekten açık kaynak standalone harness ise **P0 eksik**.

---

# 3. `route_file` bile manifestte var ama implementation yok — P0

`identity` family'de 14 tool tanımlanmış, yalnızca 4'ü mevcut.

Eksiklerin arasında:

```text
route_file
capability_lookup
capability_registry_v2
capability_gap_report
specialist_gap_report
research_plan
tool_provision_acquire
tool_provision_status
opencode_ask
opencode_status
```

var.

Bu önemli çünkü agent dokümanlarının çoğu `classify -> route -> select specialist` mantığıyla yazılmış. Ama public tree'de bunu yapan ana routing katmanı yok.

Yani agent prompt mimarisi **var olmayan orchestration sisteminin üzerine yazılmış durumda**.

---

# 4. Agent promptları gerçek kod hakkında yanlış bilgi veriyor — P0

Bence en tehlikeli gerçek bug'lardan biri bu.

`.claude/agents/recover.md` hâlâ "this package has no native x86/x64 decompiler" diyor ve `ida_query`'nin implementation'ı olmadığını söylüyor.

Halbuki `ida_query`, `ida_microcode_cfg`, `ida_type_member_offset` ve diğerleri mevcut.

`triage.md` de `ida_query` implementation yok ve kernel tarafında `kernel_triage` dışındaki `kernel_*` araçları yok anlamına gelen eski metni taşıyor.

`anticheat-driver.md` yalnız kernel first-look mevcut diye yazıyor. Ama artık kernel callback, dispatch ve IAT heuristic'leri de mevcut.

Sonuç çok kötü olabilir:

```text
Agent prompt: "IDA yok"
Gerçek runtime: "IDA var"
Agent: IDA'yı hiç çağırmıyor.
```

Yani **çalışan capability'yi kendi agent'ınız devre dışı bırakabilir.**

Daha da ilginci repo'da docs-code drift'i yakalamaya çalışan `test_docs_do_not_deny_shipped_tools.py` var, ancak test yalnızca `README.md` ve `CAPABILITIES_AND_LIMITS.md` dosyalarını kontrol ediyor. `.claude/agents/*` ve `ROADMAP.md` kapsam dışında.

Bu testin kapsamı genişletilmeli.

---

# 5. IDA entegrasyonu gerçek; kernel entegrasyonu değil — P0/P1

IDA wrapper projenin güçlü taraflarından biri. Yaklaşık **4.038 satır** ve şunlar gerçekten mevcut:

```text
ida_query
ida_microcode_cfg
ida_type_member_offset
ida_patch_plan
ida_rename_plan
ida_set_comments_plan
ida_annotations_apply
ida_annotations_purge
ida_status
```

Problem IDA'nın kendisi değil. Problem şu:

```text
FAMILIES["native"]         -> ida_query VAR
FAMILIES["windows-kernel"] -> ida_query YOK
```

Üstelik `_WINDOWS_KERNEL_PATH_ONLY_TOOL_NAMES` içerisinde `ghidra_query` var ama **`ida_query` yok**.

Yani `.sys` dosyası kernel ailesine yönlendirildiğinde projenin en güçlü decompiler/xref engine'i kernel workflow'un doğal parçası olmuyor.

Olması gereken:

```text
.sys -> kernel_triage -> IDA analysis -> DriverEntry -> functions/xrefs
     -> kernel semantic recovery -> IR
```

Mevcut tasarım daha çok iki ayrı kol gibi: kernel heuristics bir yanda, IDA diğer yanda.

---

# 6. IDA -> Analysis IR köprüsü yok — P0

`AnalysisIR` iyi düşünülmüş. Node'lar bile düzgün ayrılmış:

```text
Artifact Module Section Function BasicBlock Symbol
Import Export StringLiteral Reference Call Evidence
```

Ama README açıkça binary'den Analysis IR çıkaran hiçbir tool olmadığını diyor.

Yani IDA bir JSON, Rizin başka bir JSON, Ghidra başka bir JSON üretiyor; bunları `AnalysisIR`'a çeviren katman yok.

Sonuç olarak `native_xref`, version diff, cross-binary relationship gibi güzel sistemler mevcut olsa bile caller önce IR'ı kendisi üretmek zorunda. Harness için bu büyük bir kopukluk.

Ben P0 olarak `ida_to_ir()`, `rizin_to_ir()`, `ghidra_to_ir()`, `merge_ir()` eklerdim ve engine-specific sonuçları agent'a doğrudan göstermem.

---

# 7. README'nin "engine disagreement normalization" iddiası henüz doğru değil

README yaklaşık olarak engine'leri wrap ettiğini ve disagreement'larını normalize ettiğini diyor.

ROADMAP ise açıkça "normalising answers across engines — still open" diyor.

Yani burada doğrudan dokümantasyon overclaim'i var. Engine-independent API henüz yok.

Bu yüzden ortak abstraction ciddi ihtiyaç:

```python
class REBackend:
    functions()
    decompile()
    xrefs()
    cfg()
```

---

# 8. Ghidra entegrasyonu çok yarım — P1

Ghidra'da sadece `ghidra_status` ve `ghidra_program_facts` var.

Yok: `ghidra_query`, decompile, xref, callers, callees, CFG.

Bu Ghidra'nın yetersizliğinden kaynaklanmıyor. Ghidra'nın resmi headless API'si script çalıştırabiliyor; `DecompInterface` doğrudan fonksiyon decompile ediyor ve `ReferenceManager` xref altyapısı sağlıyor.

Dolayısıyla mevcut Ghidra slice'ı genişletmek teknik olarak mümkün.

Bu özellikle önemli çünkü IDA lisansı olmayan ortamlarda şu anda gerçek ikinci decompiler verification engine'iniz yok.

---

# 9. IDA tarafı güncel API'lere göre modernize edilebilir — P2

Mevcut sistem `idat -A` + IDAPython worker + subprocess isolation kullanıyor.

Bu yanlış değil. Hatta IDA crash'ini harness'ten ayırması iyi.

Ama IDA 9.4 itibarıyla `idalib` daha erişilebilir hale geldi ve Hex-Rays batch automation için daha düşük kaynak tüketimi nedeniyle bunu öneriyor; Domain API de functions, xrefs, types, flowchart gibi kavramları daha temiz API'lerle sunuyor. IDA 9.4'te Domain API microcode/pseudocode erişimi de genişletildi.

En mantıklısı in-process idalib değil, izole worker içinde idalib + IDA Domain olabilir. Böylece mevcut crash isolation korunur, `ida.py`'nin karmaşıklığı azalır.

---

# 10. Kernel static analysis hâlâ çoğunlukla heuristic — P1

Mevcut fonksiyonlar faydalı:

```text
kernel_triage
driver_major_function_scan
rip_relative_iat_scan
kernel_callback_registrations
ioctl_candidate_scan
ioctl_control_code_decode
```

Ama bunlar semantik analiz değil.

Örneğin dispatch zinciri `DriverEntry -> DriverObject->MajorFunction[n] -> handler` dataflow/xref/decompile üzerinden gerçekten çözülmüyor.

`driver_major_function_scan` byte-pattern adayları üretiyor ve bilinçli olarak `proves_dispatch = false` diyor.

Bu dürüst; fakat güçlü bir kernel analyzer için yeterli değil.

Eksik semantik katman:

```text
DriverEntry recovery
dispatch assignment recovery
callback argument/target recovery
device/symbolic-link references
framework identification
call graph
```

---

# 11. Kernel family'nin declared eksikleri hâlâ büyük

Mevcut **6/15**. Eksik declared capabilities:

```text
kernel_debug_analyze
kernel_security_analyze
semantic_security_analyze
native_inspect
ghidra_query
ioctl_code_recovery
iat_call_argument_recover
passive_object_namespace_probe
detection_reason_map
```

Özellikle `iat_call_argument_recover`, `ioctl_code_recovery` ve `kernel_debug_analyze` yüksek değerli boşluklar.

---

# 12. Kernel debugger / dump entegrasyonu yok — P1

WinDbg/KD wrapper yok. Kernel dump parser yok. Sadece MDMP tarafı bulunuyor.

Microsoft'un mevcut debugging altyapısı hem kernel dump'ları hem live kernel debugging'i destekliyor. İlk aşamada canlı debugging yerine **read-only dump analysis wrapper** daha güvenilir ve kontrollü başlangıç olur.

```text
kernel dump -> WinDbg worker -> structured JSON -> Analysis IR / Evidence
```

---

# 13. Emulation family fiilen boş — P1

Manifest `emulate_binary`, `emulation_status`, `emulate_range`, `emulation_unpack`, `emulate_range_status`, `tool_missing` diyor.

Gerçekte yalnız `tool_missing` var. Yani operasyonel olarak **0/5**.

Üstelik `unicorn` core dependency. Unicorn yalnız `recover/vex.py` içinde belirli instruction semantics doğrulaması için kullanılıyor.

Genel `register state -> bounded code range -> trace -> register/memory snapshots` engine'i yok.

ROADMAP de bunu projenin en faydalı missing piece'lerinden biri olarak işaretliyor.

---

# 14. Symbolic/concolic execution hiç yok — P2

Manifestte bile gerçek engine bulunmuyor.

ROADMAP: symbolic execution absent, whole-program dataflow absent, taint absent.

Bu konuda optional bir `angr` backend mantıklı olur. angr şu anda `CFGFast`, `CFGEmulated` ve symbolic execution altyapısı sağlıyor.

Core dependency yapmak yerine optional backend olarak eklemek daha mantıklı.

---

# 15. Dataflow/taint/reachability katmanı yok — P1/P2

`native` manifestinde `dataflow_recover`, `resolve_incoming_parameter_source`, `find_import_references`, `find_code_references` gibi güzel tool isimleri var.

Implementation yok.

Bu nedenle agent "bu dış girdiden şu kontrol noktasına nasıl geliniyor?" gibi soruları engine-backed şekilde çözemiyor.

`reachability` agent prompt'u var fakat ona gerekli deterministic altyapının büyük kısmı yok.

---

# 16. Devirtualization yok — büyük uzun vadeli boşluk

ROADMAP bunu projenin **en büyük single gap'i** olarak nitelendiriyor.

VM tabanlı protection karşısında native disassembler custom bytecode interpreter'ı opaque görüyor.

Hiçbir VM handler classifier, bytecode lifter, VM IR, semantic handler recovery katmanı bulunmuyor.

Bu P3 araştırma işi; ilk yapılması gereken şey değil.

---

# 17. Genel control-flow unflattening yok

IDA'nın optional d810 entegrasyonu var.

Ama repo kendi de doğru biçimde d810 desteğinin genel bir deflattener olmadığını diyor.

Engine-independent CFG recovery, dispatcher detection, state variable analysis, block ordering reconstruction yok.

Dolayısıyla flatten edilmiş fonksiyonlar pratikte hâlâ zor.

---

# 18. Function boundary recovery zayıf

PE exception/unwind (`.pdata`) parser yok.

Dolayısıyla stripped x64 binary'lerde function start, function end, unwind relationships bilgisi kullanılamıyor.

ROADMAP bunu özellikle söylüyor. Kernel binary'ler açısından da önemli.

---

# 19. PE coverage hâlâ tamamlanmamış

Eksikler: delay imports, base relocations, rich header, exception/unwind data.

TLS sonradan eklenmiş.

Rizin relocation okuyabiliyor ama kendi native PE structural modelinizde tam coverage yok.

---

# 20. ELF / Mach-O desteği çok yüzeysel

Pure Python/core tarafında sadece class, endianness, machine, file type tanınıyor.

Yok: sections, segments, symbols, imports, relocations, function discovery.

Bunlarda Rizin'e bağımlısınız. Cross-platform RE harness hedefleniyorsa büyük eksik.

---

# 21. Crash analysis stack unwinding yapmıyor

Minidump parser var ve güzel.

Ancak stack pointer scan heuristic olarak yapılıyor. Gerçek unwind değil.

Ayrıca public symbols only, no source lines kısıtları bulunuyor.

Windows crash analysis tarafında PDB + unwind desteği kaliteyi ciddi artırır.

---

# 22. Dynamic family'nin %80'i implementation değil

**8/39**. Mevcut:

```text
pe_sieve_scan
pe_sieve_status
frida_status
dynamic_lab_gate
dynamic_lab_register_owned_process
image_address_map
api_catalog
tool_missing
```

Eksiklerin arasında:

```text
isolated_dynamic_validate
dynamic_owned_process_scan
dynamic_owned_process_diff_scan
guest_checkpoint_*
guest_frida_trace
guest_frida_breakpoint_inspect
guest_screen_capture
guest_watch_collect
procmon_*
memory_scan
windbg_live_kernel_debug
windbg_user_mode_live_debug
x64dbg_*
unpack_iat_rebuild
```

var.

Yani dynamic mimarinin büyük bölümü private-tree manifesti.

---

# 23. Frida client var ama end-to-end sistem yok

`frida_trace_client.py` **1.338 satır**.

Ama kendi docs'u guest-side launcher olduğunu, host-side driver'ın ship edilmediğini diyor.

`frida_status` host'taki Frida'yı görebiliyor ama client'ı kullanmıyor.

Bu klasik "çok kod + integration missing" örneği.

---

# 24. API Monitor naming/routing bug'ı var

Bu küçük ama net bug.

`FAMILIES["dynamic"]` `apimonitor_status` bekliyor.

Ama module top-level function `def status():` adıyla tanımlı.

İçeride dönen JSON `tool = "apimonitor_status"` olsa bile `published_tools()` fonksiyon adına baktığı için capability **implementation yokmuş gibi görülüyor**.

Ya fonksiyon `apimonitor_status()` olarak yeniden adlandırılmalı, ya registry alias bilmeli.

---

# 25. Implement edilmiş ama registry/routing'e sokulmamış araçlar var

Özellikle `disassemble_pe_structured` ve `ioctl_candidate_scan` mevcut.

Ama FAMILIES içinde yoklar.

Doküman bile bunları "Python-only" olarak açıklıyor.

Harness açısından çalışan tool'un Python dosyasında gizli kalması iyi değil.

---

# 26. Birçok IDA özelliği CLI'ya bağlanmamış

CLI toplam **37 command** taşıyor.

IDA tarafında CLI'ya ulaşanlar: `ida`, `idamicrocode`, `idastatus`, `idaannotations`.

Fakat backend'de olup CLI'da doğrudan bulunmayan önemli operasyonlar var:

```text
ida_type_member_offset
ida_patch_plan
ida_rename_plan
ida_set_comments_plan
ida_annotations_apply
ida_annotations_purge
```

Private tool bus olsaydı sorun daha az olurdu. Public tree'de tool bus olmadığı için önem kazanıyor.

---

# 27. Evidence layer çok iyi düşünülmüş ama public end-to-end trust chain eksik — P0/P1

Bu kısım önemli.

`artifact_provenance.py` şunları hashlemek istiyor:

```text
<REDACTED: five upstream-only files — the system prompt, the tool
registry, the file router, the deterministic planner and the claim verifier>
```

Ama bunların public checkout'ta olmadığını kendi docstring'i söylüyor. Ve sonuç `provenance_valid = False` oluyor.

Daha önemlisi `evidence/security.py`, deliberate forgery'ye gerçekten direnç sağlayan binding'in `<REDACTED>` (upstream evidence ledger) içindeki live ToolResultStore result_id binding'i olduğunu, ardından bunun upstream-only olduğunu söylüyor.

Yani checksums/staleness kısmı public, fakat **güçlü runtime evidence binding public değil**.

Bu yüzden README'deki "claim can be traced back to the measurement" vizyonu altyapı olarak var ama standalone public tree'de tam kapanmıyor.

---

# 28. Result protokolü tamamen unified değil

Bazı public API'ler JSON `str` dönüyor: `ida_query()`, `kernel_triage()`, `rizin_*`.

Bazıları doğrudan `dict`: `disassemble_pe_structured()`, `verify_constant_at_address()`, `build_validation_plan()`.

Bu kendi başına yanlış değil. Ama tool bus yokken caller'ın her modülün kontratını ayrıca bilmesi gerekiyor.

Ortak `ToolResult`, `ToolError`, `EvidenceRef`, `Coverage`, `Confidence` modeli daha iyi olur.

---

# 29. Stable public SDK surface yok

`liebert_re/__init__.py` neredeyse boş. Alt paket `__init__.py` dosyaları da export yapmıyor.

Yani kullanıcı `from liebert_re.tools.ida import ida_query` gibi internal path'lere bağımlı. Uzun vadede refactor zorlaşır.

Örneğin `liebert_re.api`, `liebert_re.backends`, `liebert_re.models` gibi versioned public facade iyi olur.

---

# 30. `ida.py` artık monolith

**4.038 satır.** Benzer büyük dosyalar:

```text
rizin.py              ~2579
vb6_pcode.py          ~1777
cpp_rtti.py           ~1762
binary.py             ~1515
frida_trace_client.py ~1338
evidence/index.py     ~1194
msf_pdb.py             ~996
```

Bu boyutlarda test etmek mümkün ama maintainability düşüyor.

Özellikle IDA tek dosyada installation resolution, process runner, cache, locks, query, microcode, d810, annotations, journal, purge, patch planning ve status taşıyor.

Bunu bölmek ciddi fayda sağlar.

---

# 31. Lint çok dar

Ruff sadece `E9` ve `F` çalıştırıyor.

Projenin kendisi geniş default Ruff'ın **481 finding** ürettiğini ve 469'unun dense one-line style kaynaklı olduğunu söylüyor.

Black gate bilinçli olarak kapalı.

Bu yaklaşım anlaşılır ama sonuç: bugbear, complexity, security-style lint, simplification, typing kontrollerinin hiçbiri yok.

Özellikle büyük monolithic modüllerde teknik borç büyür.

---

# 32. Static typing gate yok

CI'da mypy ve pyright yok. Kodda type hint kullanımı da modüller arasında çok düzensiz.

Tool schema'larının AI tarafından tüketildiği bir projede typing normal Python projesinden daha değerli.

---

# 33. Coverage gate yok

CI pytest, ruff ve wheel smoke yapıyor. Ama pytest-cov ve coverage threshold yok.

Yani test sayısı yüksek olsa da hangi production branch'lerin gerçekten çalıştığı ölçülmüyor.

---

# 34. Dependency/security CI yok

Workflow'da pip-audit, CodeQL workflow, Bandit, SBOM, dependency audit gate göremedim.

Security tooling projesi olduğu için en azından dependency scanning mantıklı.

---

# 35. Dependency version kontratı sorunlu

`pyproject.toml` kodun Capstone 5.x / Unicorn 2.x API'sini varsaydığını söylüyor.

Ama dependency `capstone>=5.0.6`, `unicorn>=2.1.4` şeklinde; üst bound yok.

Yani gelecekte Capstone 6 veya Unicorn 3 breaking change yaparsa package yine install edebilir.

Daha doğru: `capstone>=5.0.6,<6`, `unicorn>=2.1.4,<3` veya compatibility test.

---

# 36. Python support claim'i CI ile tam örtüşmüyor

Package `requires-python >=3.10` diyor. Bu teorik olarak 3.10-3.14 demek.

CI yalnız 3.10, 3.12, 3.14 çalıştırıyor. 3.11 ve 3.13 test edilmiyor.

Kritik değil ama packaging correctness açığı.

---

# 37. Undeclared Python dependencies mevcut

En net ikisi: `androguard` ve `UnityPy`.

`pyproject.toml` dependency veya extra olarak declare edilmiyor.

Android module import edemezse bunu `ANDROID_MANIFEST_PARSE_ERROR` içine gömüyor.

Unity de `NOT_UNITY_ASSET_OR_LOAD_ERROR: ModuleNotFoundError...` dönebiliyor.

Halbuki doğru abstraction `TOOL_MISSING` + `dependency = UnityPy` olmalı.

UnityPy ve Androguard güncel olarak normal Python paketleri şeklinde kurulabiliyorlar.

---

# 38. FLOSS manifestte var ama wrapper yok

`native` family `floss_analyze` tanımlıyor. Implementation yok.

Bu bence düşük maliyet / yüksek kazanç özelliklerinden biri. FLOSS güncel olarak JSON üretebiliyor ve static, stack, tight ve decoded string çıkarabiliyor.

Repo'nun `stack_string_recover` gibi başka boşluklarına da yardımcı olur.

---

# 39. .NET yüzeyi yarım

Gerçek **4/9**.

Var: `dotnet_metadata`, `dotnet_metadata_inspect`, `dotnet_il_inspect`, `dotnet_relationship_analyze`.

Yok: `dotnet_inspect`, `dotnet_security_analyze`, `decompile_dotnet`, `decompiler_status`, `dotnet_deobfuscate`.

Metadata/IL güzel; fakat high-level reversing pipeline değil.

---

# 40. Android yüzeyi routing açısından 6/6 ama yetenek olarak tam değil

Registry açısından complete görünmesi yanıltıcı.

Eksikler: Dalvik method bytecode disassembly, `resources.arsc` resolution, deep signature verification, Android-specific deobfuscation.

Dolayısıyla family ratio burada capability depth'i doğru anlatmıyor.

---

# 41. Game-engine parsers çoğunlukla structural

Unreal: classic `.pak` only, compression limitations, encryption limitations, IoStore yok.

Godot: encrypted directory limitations, GDScript bytecode decode yok.

Dart: snapshot header only.

Unity daha geniş ama dependency problemi var.

Bunlar RE harness açısından orta/düşük öncelik.

---

# 42. No general unpacking pipeline

Var: UPX, LZMA1 helper, Rizin.

Ama genel `packer detection -> runtime unpack -> OEP recovery -> dump -> IAT rebuild -> reanalyse` pipeline'ı yok.

Manifest'te `unpack_iat_rebuild` var, implementation yok.

---

# 43. Runtime-resolved imports yok

ROADMAP/CAPABILITIES açıkça "Imports resolved at runtime by the target itself: not recovered." diyor.

Modern protected binary analizinde büyük eksiklerden biri.

---

# 44. Encrypted-at-rest code için yol yok

Diskte encrypted olup runtime'da decrypt edilen region'lar için static-only path yetersiz.

Dynamic backend de eksik olduğu için bu tam dead-end oluyor.

Bu, dynamic VM/dump pipeline'ın neden önemli olduğunu gösteriyor.

---

# 45. Testlerin sayısı güçlü ama confidence yanlış yorumlanmamalı

105 civarında `test_*.py` dosyası mevcut tree'de.

En son public CI Windows + Ubuntu, Python 3.10/3.12/3.14, lint ve wheel smoke geçiyor. Bu gerçekten iyi.

Fakat `pytest.ini` açıkça real IDA'nın heavy olduğunu, real Ghidra testi olmadığını, Hyper-V testi olmadığını, real corpus'un çoğunun unshipped/skip olduğunu diyor.

Yani **green CI = Python/wrapper contract sağlam**, ama **green CI != actual full engine pipeline validated**.

---

# 46. IDA real integration test otomatik CI değil

Default testlerde `FakeIdat` ve stub `ida_*` modülleri kullanılıyor.

Real IDA heavy ve IDA yoksa skip.

Bence ayrı bir self-hosted Windows RE runner, IDA installed, manual/nightly heavy suite kurmak çok değerli.

---

# 47. Kernel testleri büyük ölçüde synthetic

Repo bunu dürüstçe söylüyor.

Kernel işlemleri gerçek driver'larda ölçülmüş ama corpus public değil.

Dolayısıyla regression suite gerçek-world compiler/layout çeşitliliğini korumuyor.

Kendi ürettiğiniz WDM/KMDF fixture driver'ları çok faydalı olur.

---

# 48. Benchmark sonuçlarının bir kısmı reproducible değil

ROADMAP "quoted real-target measurements are from private corpus and cannot be reproduced from this repository" diyor.

BENCHMARKS'ta da önceki test sayıları birbirleriyle çelişmiş.

Bunlar mümkünse public generated fixtures + publicly redistributable challenge corpus metadata + expected hashes/results ile ayrılmalı.

---

# 49. Docs maintenance otomatik değil

`CAPABILITIES_AND_LIMITS.md` kendi maintenance bölümünde snapshot tarihini **1 Ekim 2026** olarak söylüyor.

Current commit **5 Ekim 2026** ve yalnız dört gün içinde kernel 2 -> 6, crypto 4 -> 5 drift etmiş.

Capability docs el ile tutulmamalı.

CI'da `generate-capability-doc` + `git diff --exit-code` tarzı kontrol lazım.

---

# 50. Issue tracker known gaps'i temsil etmiyor

Şu an açık GitHub issue yok.

Ama ROADMAP onlarca gerçek gap içeriyor.

Bu yüzden proje yönetiminde ROADMAP prose ile actionable issue backlog ayrışmış.

Katkı kabul edecek açık kaynak proje için iyi değil.

---

# En önemli declared-but-missing alanlar

| Öncelik | Eksik |
|---|---|
| **P0** | Standalone tool bus / orchestration |
| **P0** | Capability single-source-of-truth |
| **P0** | Agent prompt drift düzeltmesi |
| **P0** | Engine -> AnalysisIR |
| **P0** | Kernel routing içine IDA |
| **P1** | Kernel semantic analyzer |
| **P1** | Ghidra decompile/xref/CFG |
| **P1** | Bounded emulator |
| **P1** | Evidence runtime binding |
| **P1** | Public route/planner |
| **P1** | WinDbg dump integration |
| **P1** | Exception/unwind function recovery |
| **P1** | Runtime API/import recovery |
| **P1** | FLOSS integration |
| **P1** | CLI/tool-bus exposure cleanup |
| **P2** | angr/symbolic backend |
| **P2** | whole-program dataflow/taint |
| **P2** | PE parser completeness |
| **P2** | .NET decompile/security |
| **P2** | ELF/Mach-O first-class support |
| **P2** | dependency/package cleanup |
| **P2** | typing/coverage/security CI |
| **P2** | IDA Domain/idalib modernization |
| **P3** | general deflattening |
| **P3** | virtualization/devirtualization |
| **P3** | advanced Android obfuscation |

---

# Önerilen sıra

Yeni tool eklemeye bir süre ara verirdim.

**Aşama 1 — Harness'i gerçekten harness yap.**

```text
CapabilityRegistry -> ArtifactRouter -> Planner -> ToolExecutor
 -> EvidenceStore -> AnalysisIR -> Agent
```

Bunların public, minimal versiyonlarını getir.

**Aşama 2 — üç backend'i normalize et.**

```text
IDAAdapter / GhidraAdapter / RizinAdapter -> REBackend protocol -> AnalysisIR
```

**Aşama 3 — kernel'i bunun üstüne kur.**

```text
driver.sys -> PE/kernel triage -> IDA/Ghidra -> kernel semantic pass -> IR -> evidence
```

**Aşama 4 — bounded execution ekle.** Önce Unicorn range emulator, sonra gerekirse angr/symbolic.

**Aşama 5 — dynamic lab.** İlk olarak dump/offline debugging, daha sonra isolated guest orchestration.

---

# Korunması gereken güçlü taraflar

`bounded_subprocess` yaklaşımı iyi. IDA cache ve subprocess isolation iyi. Evidence'da staleness ve explicit-unknown yaklaşımı iyi. Tool sonuçlarında "bulamadım" ile "yok" ayrımına ciddi emek verilmiş. Synthetic fixture üretimi iyi. Current CI'ın Windows + Linux + üç Python sürümünde yeşil olması da artı.

Bu yüzden yaklaşım "projeyi çöpe atıp V2 yazın" olmazdı. Daha doğrusu mevcut sağlam tool'ları ortak backend interface, IR ve gerçek orchestration ile bağlamak.

## Son karar

Liebert şu anda beklenenden daha güçlü bir RE toolkit, ama repo adındaki "Harness" kelimesinin vaat ettiği seviyeye ulaşmasını engelleyen bir mimari kopukluk var.

En kritik sorun:

> Yüzlerce tool ismi ve onlarca gerçek implementation var; ama çalışan tool'ları
> doğru zamanda seçen, sonuçlarını tek temsile dönüştüren, kanıta bağlayan ve
> sonraki adımı deterministik yöneten public execution spine yok.

Bu çözülmeden 50 tane daha analyzer eklemek projeyi yalnızca daha büyük yapar.
Bu çözülürse mevcut IDA/Rizin/evidence altyapısı çok daha değerli hale gelir.
