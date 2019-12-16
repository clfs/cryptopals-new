# 11. An ECB/CBC detection oracle
import lib.analysis as analysis
import lib.oracles as oracles


def detect_mode(ct: bytes) -> str:
    return "ECB" if analysis.is_aes_ecb_ct(ct) else "CBC"


def test_solution() -> None:
    oracle = oracles.EcbOrCbc()

    for _ in range(100):
        response = oracle.response(bytes(50))
        want = oracle.last_mode
        got = detect_mode(response)
        assert want == got
