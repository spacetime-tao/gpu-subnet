"""Make a chain-ready weight vector without floating-point clipping."""

from fractions import Fraction
from math import ceil

from .roster import ChainError

U16_MAX = (1 << 16) - 1
_U64_MAX = (1 << 64) - 1


def encode_weights(weights: dict[int, int], cap: int) -> dict[int, int]:
    """Clip positive work to a common threshold and encode it as max-scaled u16."""
    if type(cap) is not int or not 0 <= cap <= U16_MAX:
        raise ChainError("chain returned an invalid maximum weight limit")
    if not weights:
        raise ChainError("there is no positive eligible work to submit")
    if any(type(uid) is not int or not 0 <= uid <= U16_MAX for uid in weights):
        raise ChainError("weight destinations must be unsigned 16-bit UIDs")
    if any(type(work) is not int or not 1 <= work <= _U64_MAX for work in weights.values()):
        raise ChainError("relative work must contain only positive unsigned 64-bit integers")
    if len(weights) * cap < U16_MAX:
        raise ChainError(
            "too few positive eligible miners to satisfy the subnet's maximum weight limit"
        )

    descending = sorted(weights.values(), reverse=True)
    remaining_work = sum(descending)
    remaining_cap = U16_MAX
    for work in descending:
        if work * remaining_cap <= cap * remaining_work:
            break
        remaining_work -= work
        remaining_cap -= cap

    # A clipped target uses cap units of the normalized total, leaving
    # remaining_cap units for the unmodified work still in the sum.
    cutoff = min(Fraction(descending[0]), Fraction(cap * remaining_work, remaining_cap))
    scale = U16_MAX / cutoff

    # A largest entry remains U16_MAX. Rounding other positive entries up
    # keeps them representable and can only lower the largest share.
    return {
        uid: min(U16_MAX, ceil(work * scale))
        for uid, work in sorted(weights.items())
    }
