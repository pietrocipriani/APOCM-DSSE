# APOCM-DSSE


AF_UNIX address: dsse_apocm

### Update
- Mappa key(512)-value(512+64+512)
- Per ogni documento: AEAD
    - AD: UIID(128) + length(64) + document(length)

### Search
- t(256) + KT(256) + Con(64)
- Eid(512) + con(64)
- n*UIID(128) + Con(64) + t(256)


data race search: con cambia nel frattempo.


- add
- remove
- search
