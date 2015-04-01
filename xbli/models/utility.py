"""
Model related utilities
"""

import mongoengine as db
import zlib


class CompressedBinaryField(db.BinaryField):
    """
    A Binary field which is encoded in zlib format
    """

    def to_python(self, value):
        """
        Decompress the value
        """

        if value is not None:
            try:
                value = value.decode('zlib')
            except zlib.error:
                # silently fail on already decoded data
                pass

        return super(CompressedBinaryField, self).to_python(value)

    def to_mongo(self, value):
        """
        Compress the value
        """

        if value is not None:
            value = value.encode('zlib')

        return super(CompressedBinaryField, self).to_mongo(value)
