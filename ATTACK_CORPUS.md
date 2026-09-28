# Attack corpus

The demo ships 6 documents through the gate: 2 clean (a return policy, team
notes with the phrase "act as a team" — the false-positive guard), 1 suspicious
(base64 blob with a printable-payload receipt), 3 blocked:

1. Instruction override + exfiltration request
2. DAN / developer-mode role escape
3. Cyrillic homoglyphs (uniсode) + delimiter stuffing — caught after the
   1:1 confusables fold, then redacted and wrapped

New attack styles slot into the same weighted-rule table with a named rule,
a span, and a weight — the detector reports what fired and why.
