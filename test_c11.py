"""11. An ECB/CBC detection oracle."""
import lib.analysis as analysis
import lib.oracles as oracles


def detect_mode(ct: bytes) -> str:
    return "ECB" if analysis.is_aes_ecb_ct(ct) else "CBC"


def test_solution() -> None:
    oracle = oracles.EcbOrCbc()
    query = bytes(50)
    for _ in range(100):
        response = oracle.response(query)
        assert oracle.last_mode == detect_mode(response)
