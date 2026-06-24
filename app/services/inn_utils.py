import re
from typing import List, Optional, Tuple


def validate_inn(inn: str) -> bool:
    if not inn.isdigit():
        return False
    if len(inn) == 10:
        coeffs = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(int(inn[i]) * coeffs[i] for i in range(9)) % 11 % 10
        return checksum == int(inn[9])
    if len(inn) == 12:
        c1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        c2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        n11 = sum(int(inn[i]) * c1[i] for i in range(10)) % 11 % 10
        n12 = sum(int(inn[i]) * c2[i] for i in range(11)) % 11 % 10
        return n11 == int(inn[10]) and n12 == int(inn[11])
    return False


def parse_inns(text: str) -> List[str]:
    labeled = re.findall(r"(?:инн|inn)[:\s№#]*(\d{10}|\d{12})", text, re.IGNORECASE)
    if labeled:
        return labeled
    return re.findall(r"\b(\d{10}|\d{12})\b", text)


def analyze_inns(text: str) -> Tuple[Optional[str], bool, bool]:
    inns = parse_inns(text)
    if not inns:
        return None, False, False
    primary = inns[0]
    return primary, True, validate_inn(primary)
