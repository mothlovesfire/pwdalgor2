from argon2.low_level import Type
import math

import EntropyStream

def next_power_of_two(x: int) -> int:
    return 1 << x.bit_length()

# printable characters
setLower = "abcdefghijklmnopqrstuvwxyz"
setUpper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
setNumber = "0123456789"
setSymbol = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
setAllPrintable = setLower + setUpper + setNumber + setSymbol

# fields
fieldPasswordLengthRangeMin = 8
fieldPasswordLengthRangeMax = 24
'''
    add fields for number of required symbols/uppercases/something like that
'''

fieldPasswordRequiredUpper = 3
fieldPasswordRequiredLower = 0
fieldPasswordRequiredLetter = 2
fieldPasswordRequiredNumber = 4
fieldPasswordRequiredSymbol = 2

fieldPasswordRequiredLetter = max(0, fieldPasswordRequiredLetter - fieldPasswordRequiredUpper - fieldPasswordRequiredLower)
fieldPasswordRequiredSpecialCasesCount = fieldPasswordRequiredUpper + fieldPasswordRequiredLower + fieldPasswordRequiredLetter + fieldPasswordRequiredNumber + fieldPasswordRequiredSymbol

estimatedBytes = fieldPasswordLengthRangeMax + fieldPasswordRequiredSpecialCasesCount + 1
print(f"estimated number of bytes used: {estimatedBytes}")
print(f"optimal hash length: {next_power_of_two(estimatedBytes)}")

# arguments
argSecret = b"moth loves fire pats and pons"
argSalt = b"site=example.com|pin=1201|icecreamflavor=icecream"
argTimeCost = 5
argMemoryCost = 65536
argParallelism = 16
argHashLength = next_power_of_two(estimatedBytes)
argType = Type.ID
argVersion = 16



byteStream = EntropyStream.EntropyStream(argSecret, argSalt, argTimeCost, argMemoryCost, argParallelism, argHashLength, argType, argVersion)
byteStreamIterator = iter(byteStream)

calcPasswordLength = fieldPasswordLengthRangeMin + (next(byteStreamIterator) % (fieldPasswordLengthRangeMax - fieldPasswordLengthRangeMin + 1))
print(f"password length = {calcPasswordLength}")

encodingSets = ["All"] * calcPasswordLength

indexRange = list(range(calcPasswordLength))
encodingSetsQueue = ["Upper"] * fieldPasswordRequiredUpper + ["Lower"] * fieldPasswordRequiredLower + ["Letter"] * fieldPasswordRequiredLetter + ["Number"] * fieldPasswordRequiredNumber + ["Symbol"] * fieldPasswordRequiredSymbol
print(f"encoding sets queue: {encodingSetsQueue}")

while len(encodingSetsQueue) != 0:
    selectedIndex = indexRange.pop(next(byteStreamIterator) % len(indexRange))
    encodingSets[selectedIndex] = encodingSetsQueue.pop(0)
    # print(encodingSetsQueue)

print(f"encoding sets: {encodingSets}")

password = ""
for set in encodingSets:
    selectedCharacter = next(byteStreamIterator)
    if set == "All":
        password += setAllPrintable[selectedCharacter % len(setAllPrintable)]
    elif set == "Upper":
        password += setUpper[selectedCharacter % len(setUpper)]
    elif set == "Lower":
        password += setLower[selectedCharacter % len(setLower)]
    elif set == "Letter":
        password += (setLower + setUpper)[selectedCharacter % len(setLower + setUpper)]
    elif set == "Number":
        password += setNumber[selectedCharacter % len(setNumber)]
    elif set == "Symbol":
        password += setSymbol[selectedCharacter % len(setSymbol)]

#print(setFullPrintable)
#print(len(setFullPrintable))
print(f"password: {password}")
#print(f"length of generated password: {len(password)}")