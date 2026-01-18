from argon2.low_level import hash_secret_raw

class EntropyStream:
    def __init__(self, argSecret, argSalt, argTimeCost, argMemoryCost, argParallelism, argHashLength, argType, argVersion):
        self.bytes = hash_secret_raw(
            secret = argSecret,
            salt = argSalt,
            time_cost = argTimeCost,
            memory_cost = argMemoryCost,
            parallelism = argParallelism,
            hash_len = argHashLength,
            type = argType,
            version = argVersion
        )

    def __iter__(self):
        self.indexCurrent = 0
        return self
    
    def __next__(self):
        if self.indexCurrent >= len(self.bytes):
            raise StopIteration
        # print(f"using byte {self.indexCurrent}")
        self.indexCurrent += 1
        return self.bytes[self.indexCurrent - 1]