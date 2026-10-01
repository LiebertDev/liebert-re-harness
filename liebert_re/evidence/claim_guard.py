"""Deterministic exact-evidence and negative-claim checks shared by runtime/tests."""
import re
def claim_guard_issues(answer,evidence):
    answer=str(answer or '');evidence=str(evidence or '');low=evidence.lower();issues=[]
    for ref in sorted(set(re.findall(r'(?i)\b0x[0-9a-f]{5,16}\b',answer))):
        if ref.lower() not in low:issues.append(f'Tool evidence icinde bulunmayan exact hex reference: {ref}')
    for m in re.finditer(r'(?i)\blines?\s*[~≈]?\s*(\d{2,6})(?:\s*[-–]\s*(\d{2,6}))?',answer):
        for n in [x for x in m.groups() if x]:
            if not re.search(rf'(?m)(?:^|\n)\s*{re.escape(n)}:',evidence):issues.append(f'Tool evidence ile dogrulanmayan line reference: {n}')
    imported=set(re.findall(r'(?i)\b[A-Za-z0-9_.-]+\.dll!([A-Za-z_][A-Za-z0-9_@$?]*)',evidence))
    for func in imported:
        f=re.escape(func);patterns=[rf'(?i)\bdoes\s+not\s+import\b[^\n.]{{0,80}}\b{f}\b',rf'(?i)\bno\s+(?:explicit\s+)?import\b[^\n.]{{0,80}}\b{f}\b',rf'(?i)\b{f}\b[^\n.]{{0,60}}\bnot\s+imported\b',rf'(?i)\b{f}\b[^\n.]{{0,60}}\bimport\s+yok\b',rf'(?i)\b{f}\b[^\n.]{{0,60}}\bimport\s+edilmem']
        if any(re.search(x,answer) for x in patterns):issues.append(f'Import absence claim evidence ile celisiyor: {func}')
# Hedging/negation detection is deliberately multilingual: the regexes below
# carry Turkish negation and "no evidence" phrasings alongside the English ones,
# because model output being checked is not guaranteed to be in English. These are
# detection patterns, not user-facing text -- do not "translate" them away.
    neg=r"(?:no|none|never|does\s+not|doesn't|yok|bulunmuyor|kullanmıyor|kullanmiyor|içermiyor|icermiyor)";domain=r"(?:network|registry|console|encryption|packer|packing|anti-?cheat|telemetry|socket|şifreleme|sifreleme)"
    risky=re.compile(rf"(?i)(?:\b{neg}\b[^\n.]{{0,100}}\b{domain}\b|\b{domain}\b[^\n.]{{0,100}}\b{neg}\b)")
    cautious=re.compile(r'(?i)NO EVIDENCE OBSERVED|UNKNOWN|ANALYSIS_LIMITED|kanıt\s+(?:yok|gözlenmedi)|kanit\s+(?:yok|gozlenmedi)|mevcut\s+evidence')
    for line in answer.splitlines():
        if risky.search(line) and not cautious.search(line):issues.append('Yuksek riskli negative claim temkinli evidence dili kullanmiyor: '+line[:180])
    return sorted(set(issues))
