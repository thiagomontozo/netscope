# Risk Model

Severity describes intrinsic technical seriousness. Priority describes what the organization should address first. Confidence describes evidence quality. They remain separate.

## Transparent factors

The initial engine evaluates scanner/observation severity, confirmed known exploitation, approved public exposure, asset criticality, observed affected service, confidence and age. Each factor and its direction is saved with the finding.

A simple ordinal implementation may start from severity and apply documented one-step adjustments: raise for KEV plus service presence, public exposure or critical asset; reduce for low confidence, absent service evidence or stale observation. Caps prevent a low-confidence signal from becoming critical priority solely through CVSS. Analysts see factors and can override with an audited reason.

The model does not produce a probability of exploitation, does not claim compromise and does not hide weights in an opaque score.
