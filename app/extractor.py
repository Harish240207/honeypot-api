import re

def uniq(lst):
    return list(dict.fromkeys(lst))

def extract_intel(full_text: str):
    full_text = full_text or ""

    upi_ids = re.findall(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b", full_text)
    urls = re.findall(r"https?://\S+", full_text)
    accounts = re.findall(r"\b\d{9,18}\b", full_text)
    ifsc = re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", full_text.upper())
    phones = re.findall(r"\b(?:\+91[-\s]?)?[6-9]\d{9}\b", full_text)

    return {
        "upi_ids": uniq(upi_ids),
        "bank_accounts": uniq(accounts),
        "ifsc_codes": uniq(ifsc),
        "urls": uniq(urls),
        "phone_numbers": uniq(phones)
    }
