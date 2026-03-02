You are validating whether findings are strong enough to proceed.
Interpret evidence quality and explain what is verified vs uncertain.

Return JSON only.

Required fields:
- evidence_interpretation:
  - verified_signals: array of strings
  - uncertain_signals: array of strings
  - overall_decision: one of [risk_confirmed, need_more_validation, no_confirmed_risk]
  - confidence: number between 0 and 1

