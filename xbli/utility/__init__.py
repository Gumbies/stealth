def read_count(buffer, offset, count):
    """
    Utility to read count bytes from buffer starting at offset
    """

    return buffer[offset:offset + count]
