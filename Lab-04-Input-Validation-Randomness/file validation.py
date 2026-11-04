import re

def validate_filename(filename):
    filename = filename.strip()

    # Empty filename
    if not filename:
        return False, "Filename cannot be empty."

    # Hidden files such as .env
    if filename.startswith("."):
        return False, "Hidden files are not allowed."

    # Explicit path traversal protection
    if ".." in filename:
        return False, "Path traversal is not allowed."

    # Reject directory separators
    if "/" in filename or "\\" in filename:
        return False, "Directory paths are not allowed."

    # Allow only letters, numbers, underscore and period
    if not re.fullmatch(r"[A-Za-z0-9_.]+", filename):
        return False, "Only alphanumeric characters, '_' and '.' are allowed."

    return True, "Filename accepted."