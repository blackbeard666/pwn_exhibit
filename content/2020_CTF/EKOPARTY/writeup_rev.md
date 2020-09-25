## EKOPARTY: entry [1 - 5], C&C [1], Trivia [1]
#### These are the only challenges I solved during the ctf. This was a new experience for me as I got to somehow experience challenges catered for malware analysts. I need to learn more about reversing and malware analysis to be able to solve more challenges in this event in the next editions.

## Entry 1: exe
> A common hash function used to identify malware is SHA256, may you please tell us what is the value of the hash for this malware sample?

#### Pretty straightforward, we just need to get the sha356 sum of the provided malware sample, then convert it to uppercase letters.
![](entry_sha.png)

#### Flag: `EKO{EBA35B2CD54BAD60825F70FB121E324D559E7D9923B3A3583BB27DFD7E988D0C}`

## Entry 2: ABCD
> What's the name of this famous malware?

#### Again we are provided with another malware sample, which our goal is to find its name. For this, we can upload the sample to virustotal and scan it against its database.
![](entry_ryuk.png)

#### Flag: `EKO{ryuk}`