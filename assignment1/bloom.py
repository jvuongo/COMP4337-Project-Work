# pip install mmh3
# pip install bitarray
from bitarray import bitarray
import mmh3
import re

class BloomFilter(object):
    
    # Constructor    
    def __init__(self, filter_size):

        # Size of the filter being used
        self.filter_size = filter_size

        # Generate a bit array of the given size
        self.bit_array = bitarray(filter_size)

        # Set all bits to 0
        self.bit_array.setall(0)


    # Returns the bits in the bit array
    def __str__(self):
        return self.bit_array.to01()

    # Add the key to the bloom filter
    def add(self, key):
        digests = []
        for i in range(3):

            # Create digest for given item.
            # There are currently 3 seeds to create a digest
            digest = mmh3.hash(key, i) % self.filter_size
            digests.append(digest)

            # set the bit True in bit_array
            self.bit_array[digest] = 1

        print(f"EncID Digest: {digests}")

    # Reset all bits to 0
    def reset(self):
        self.bit_array.setall(0)

    # Return a list of positions that are 1 bit.
    def get_DigestPos(self):
        iterator = re.finditer('1', str(self.bit_array))
        digestPos = [bit.start(0) for bit in iterator]
        return digestPos
    
    def merge(self, filters_list):
        self.bit_array.setall(0)
        for dbf in filters_list:
            self.bit_array |= dbf.bit_array
