def red(text: str) -> str:
    return f"\u001b[31m{text}\u001b[0m"

def green(text: str) -> str:
    return f"\u001b[32m{text}\u001b[0m"

def bold(text: str) -> str:
    return f"\u001b[1m{text}\u001b[0m"

def italic(text: str) -> str:
    return f"\u001b[3m{text}\u001b[0m"

def underline(text: str) -> str:
    return f"\u001b[4m{text}\u001b[0m"

def truncate(text: str, maxlen: int) -> str:
    return f"{text[:maxlen]}{'...' if len(text) > maxlen else ''}"
