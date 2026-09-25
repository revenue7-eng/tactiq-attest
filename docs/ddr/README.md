# Design decision records

Each record states what was decided about this repository's code, why, what
was rejected, and what was observed when it was tested. Code comments cite
them as `DDR-00N decision M` or `boundary X`.

| DDR | Subject | Status |
|---|---|---|
| [DDR-004](DDR-004-quote-envelope-v2.md) | Envelope v2: the signed object is a `TPM2_Quote` under a restricted AK | accepted, implemented |
| [DDR-005](DDR-005-ak-registration.md) | Registering the AK against the TPM endorsement key | accepted, not implemented |

DDR-001 to DDR-003 belong to a closed component and are not published here.
Most comments that cite them also state the decision they rely on, in place.
A few are bare citations; read those as pointers, not as rules you can check
from this repository.

A record is changed only by adding to it or by a later record that amends it,
named in the header of both.
