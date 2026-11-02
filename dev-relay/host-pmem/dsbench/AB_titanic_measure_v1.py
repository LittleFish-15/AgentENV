"""Titanic candidate A2+B2: original trajectory, pread and private RAM; backing held.
Existing native components are reused; no build, SDK mutation or module change.
Raw evidence stays under /home/jwk/root; only bounded derived receipts go GitHub.
"""
import argparse,base64,concurrent.futures,fcntl,hashlib,http.client,json,os,re,shlex,socket,stat,struct,subprocess,sys,threading,time,tomllib,types,zlib
from pathlib import Path
BASE=Path('/home/jwk/root/hpt-services-v1');HOME=Path('/home/jwk/root/titanic-measure-v1')
SESSION='relay-20261029-0d032371';RUN='titanic-full-20261102-v1'
RESULTS='LittleFish-15/AgentENV-relay-results';CONTROL='LittleFish-15/AgentENV-relay-control'
SPEC='titanic-experiments/'+SESSION+'/'+RUN+'/contract.json'
SERVICE_PIN='445e26e1f239c5244f0e2957b2b94742039dc5d2398ca04cb167d94f230837f9'
PROBE_PIN='18855dff8f72ad945d4f9e6225344adeae24b111e0028194e323f0539bdb026f'
OWNER_PIN='1ca1717821569dfc4e36f12e01e7359da0de76919742e6cf3978ef7ab0df9e7c'
COMMAND_FAILURES=[]
CONTRACT_SHA=''
BUNDLED={'REPLAY': {'sha256': '2e0f31142d8fca47724f319c96aae8758f4b0a07d051614a1d92537a9f23a259', 'z64': 'eNp1VduO2zYQfd+vmAoJJMGS17tB8iBFCPLgBgs0QbEJigK2YdDSeM21RKokfUvTf++QlGwh6/hBpuZy5nJmKN60Uhl41lIkChO9qfF4U+EaBGIVyW0CDWrNnjDOboB+nDTSgNxmoBjXCI87YXiDU6WkinrbGw8hVcNq/h2XrDRcisj/dUhBEDyIClukhzDAm7bGhk7M2oBcg9kgKNxzPGBFBzJTWKVYcSMVlFLsyZhMxwTkAI06ZQepKl24Ksa6rbnpYzoLPJbYGviL1TufcKbQ7JQAb9QX6EBm2f3it2IWaqOWCtualbj0scNkKAwXV0BsKq3U3Ap0MXOAY04VHKN1zZ7i0R2sqQh7Bi4gCtNU1tWSYAk8TQUe3Dle5Hubaw8x4wvnx63TGX8xrC26FJfY9h7dMb6So2XIKN5ELkRHStcBJxprw5TRB242UThXcxHGmVMU7jm7zxZnH6yve/3sczfwOXsQtb+OkqX3V8MMnF663F1cusKdxgm7jtZcm6hhbWR7kHhhHA9n3Mtmk2sEOxaSveXhO2+jMxc9UNbzVexvBln4wXyWXETOoFsUbbDVy7WSTaTYoaOiYoYVdi/HtWSVdppcyQMNwyI3qBouWF18kQIvGRlsbErWdRYaxZ6xpIE90YwOu26L45oLYkqUGFmvpOKliYEwrijHT2ii0FcfxglN5sWS1LNetSDuFXUjzmg7DRddw+3PWxTXzYe5eR2VfEAVxX459G7VcEObseaC6w0dKqqaSD93wXvlK4Vse0arsGan4lKAe1/ayypMJpeg7qIzpxYjZ+BjcmGSNfWdesJEBZP3hVO+f/NuMknCB0E08wouHfbBwguqJWrMWnu7Rf/2FWe/uhETn1yYuZhdIv95NJefhUvCadOaE206ljvDVjUOEghpNvyMOdO+M918bbCul6VsGiqmi5k0TG1R9de6EKiKQKOBkYSWt7hmvM4plvs8/Pnx0/SxKJk5Sz5//PJS+Onh2/Kl9I/p169F+vvj3zmUFaQp3MKPH6TkBu7u3+YQjAaL1RURukwwh1v6nAiDYn+74uJ2tdOnlTyCJVHuDKQavk0fP0O6hbfwZjIBb8X0BtIa0hLCkV+5f3bS0DDbKuNRQInICotXH3JoFVG9hnA+F8HIt2QUwGtN7yHMg1fWcB7kPt1J8D+2JGG+'}, 'GROUP': {'sha256': '49c650a4fd7383d4cf24876b440bb2dbd9460719b4ef980778ed688ee9a9e095', 'z64': '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'}, 'ENGINE': {'sha256': '5d0cd8d4cf45b8301532517af832710c3928458f20c1cc64b0991500ddb1b89d', 'z64': 'eNrFPGtz27aW3/UrsOkHSr2y4ri5na67nl0ndlvPtonHdmZn1+PhhUXY4jVF6gKkHd2M//uec/AgQIKS4nRnPW1iieDBwXm/kFevXr2rmjITGTs+P2NFfifm63kh2FNeL9iTzGuxxxeCZ0yKfzRC1Uw85pko54LxMmPVUwlvwnpeNqvZaPShgnXLqhZM3AGkWrGqZPlyVcl6xq4Wgs15UQjJFlWRKVbDF5lYFdV6Kcr69bxawDpWVPMHdlfJET6eV8tVIQCebMoZ+1Q+lLAlO/94ecWqpoanQuGOPC/ZSpRZXt4DgqJkTwv4Iy/h17qSa5ar0byREj4VayaWq3p9yDir86XI9gCOO9ycl0zVeVG0G8MBEBEl5KOQs9GrV69G+kCwZLW2v0thf0Og9vemybPRaJSJO9ohl2JcPUzhd66qcnI4YvCT37Gyqln1oD/ij+S5EuyiKRHWqZSVHJtXDDDkQJ3f5UKOH3nRCAPK7pGrvFQ1Bybpx1M4k5wQw6SY3TVFseT1fDGWyfXx3v/wvX/u7/1runfz5c30zcFPz8mUaaBThxD+JH/kSiF9K4mE5UWuRUbjUq+TicGhbmSpIRhsASmh5rBqDEjVLbK0UH83uxf1OAECq7wqkwk7OmJvCF/v6WrBlYBnwGr4IMWKS5EBsomBnxkM7E/ndQWfb6vPZ5nS8K9vuisqkKALLQhuzSaIRgA/AZ1lDRKIuCn2Cy+UsIzicxTYQmT3IkstpcYPeZlNCVKjUBpWxdoQBaTrHIkAoliVIKq3RjfNq3DOKStBwCWRvq4eRKmQIdWKA94ASq2qUgk1QzFFgLVct3IFooZb48mSOUhULRJ3pkbh1wf7muyeBBF6U5bl83pyGJDDcPCLT9pDdu0JJ70bkv8kmUxunqMogc4/7I5QAUTSMl2IUn+p5aaDZPXEjjSNr/dDdsLePtjqyZxSK0r1pBEXqH+atR+qUvSwsevMAZNJlFY70qt6unaAbnYm3JyvAHLITNSSg/39KVJw8hKelnylFlV9lgGOAyy1SxA1jZn4PBerOjBdLfwVV8pXfSSns47gQpRIzUnUmK9yrSFgvFZaI1BT5pXMWlU5/bwq8nmONh29zqPQSlMvgFd/r2ALXiSKGZgZOztBlyOr5n5BJh1UCFwWwvqbhjzOs8nfDHbaOxmngd5gmde1yAwOAPbyt2PUPJIJ8jb8VsHSGQE8ZiuZw9PG2gZ2cvr76dUpShHhOF+I+QOAA5nXL86F1WwpwNA2ItOQrMvT+qpeWwq9/gW0RTFePPG1YrfkNOngYMUkr8GMziyZAt+w2dyiJxqwmWBoP5K3/5UMJFs2YKRuhWUdHCWXqjY22IoG6HAAz37tnIW2tuGq0A4PeTYHq2sK3IMJ+zd7rkD2NWTzWs/AQ4AylhoRVDBNnSQTGAykgabJjhpk2jm1Z0fmorN05+y61E8lcLIqHgVSvtwzpGzJotlqNmWEAzFM65oNxKIkPjVPwUFe3+gXUNEUfxRjT+fpzeu+K7sBqLdVVYztAp8nNy3VjG4az+62oRDL38cyEPR6hjHgOPn19Aqd9+vHg9dGzIT69yIHNTt6o4mu7RdgD8vAopQQfLxe8QZlrY3srBjSjoYygdMzqLjPyBSVIwgSAE9cupbQKowcYxw3+/Tp7GQMb04IOfgF0HrfYY19CxQToNegiQXGlFWZw6EZQrBaDoEmhFBcdYIW8ACoDdeC8BSIpeMzmHwRETmNzE0UeXKNANJT8SACTK4h9ON7dzdffnyLgR+uBTepd3FG74Js3uWCH/z1R+QZmPtpz7uRQH+U+X1e8sIzmFZ6IXpbsKWOIX9GI4tWkSJrc5gOJcTnFSQQAODIYnU9gFHn6CDLqBPJ6xpYX5DRTNhfkEbBOm2ggdSyr6dIavkCUhNMz+x4toTQ0iA0hp4Fkf5paIk7vENNgx4g+7lJfSytrSHJcsjCJBgiWS21P7O+0LixkOTW2x2ZxyTt3ZDJLgJXg94C/V8s1NFEcRDbI6HW9IRjvuAlhMg/A8hQl4AbvcAekCBqbN/Wj9m6loe4MAGxQuTe7r+Nk1aTV4IOVo0LJTxnDg6+KsHzLQ3yCggHm5kFQyfwfB8Qmw7TDU7xZynqRYUKkFycvv/44f3Z76cnKWCfArrp8YeTFL++OEmP312efrhKQvUpQl5t5tNW4rTpH7gk0G8tICBgit9LAfaO6gUQUW08KUV8w6c8/v3i9Pjkv815UjjyL2cXf5yedE+mIif5joFNwKAK3Fat4zuy/JS456Zcgd+u8rJ0CgAHgF8ggIzAuxWgfMIsxJOTsYJfCgFep6YYCzSzdkFfgGTH63QJ7ilYVzlClWjR0CqtN9xI5S9JjkE7OS384+14MluIzwCbAprDXjQDT7R5OtSMH1YF1IYgM9BuMDBgh/5pIC6Q8NsHzHQwJZjhH2mpxpPnoROoGV9hLcdGav2jmphEFwQwUkk0dYA3LoNI+m9R6BMFhml4CnBaNdAKbDVhSrjDb0dvDvaHmeqnrW89VhprgObSsxYrwBKLSptZuot2Gr/eSpTR9w0m7b3zFFg7oxoCKfZrrCuYaNC6jwhmrc7qs6Vw4F0tkwu4Zjppi3oZK81bvQwJjAG0TWBcagQhrBWyL99/b14DhjnuvFuDvOpDwtd3eZmrRVyKw810IK5EDUEwbwry7To9unSpD4W0bvuvUadNarnLT/R83ROEWtK1Y33Vc9W37hqjiReaAO9NPZVeupJN6we8HU354JT+QvPKFRNhEWE7cCrAbV5PhQla/CWp1ys0fPjXmPaazNK05MDfdHeCJ7o+ixyEdEGDuT78cR9UNKwy0aNpUCCZ7LwLej6WnJUK5cHZj6zjGzxrkAT1Iqsuh6PNxrQUIlMpQijnOeQolHPG2GXqOARhNBrNC64Ue09V/EOXCqYpaE+dpmMlirspixZ2qls6yRQEQMzJ3gK/+Dyv11NnLqbs+yl2AdI8OxowbkAQSpXW6T3A16ucq07vGy71q5G8tFujnnpR3y2mStYSuYUU7pXiCXHCQL96CsI8PO1MHxZ/M0fVPsadPFztqECfDCngjS51wrc8SuFHSy54r0/D8M2QXOb9kFyUCoSrwgUhRKId7lyt1rNMiBX+4tcG2r2JkQhe/4K1sk68MurHTNHM9YcDzFw9qMi8M9OhMLwLexQhvrNmlcFfY3j5LDvy4ACbUCmOEj6v80cMk5zrOrq+mbaVNvq4QYsVR/OkX3qq5ENR8Ux/cv22c1AdkR2Z5kGApCuxOIwno7Ceg0/8mo5buLGw468aqO5s358agEa10Y+HhhrjqtsqW2OJyuhDp/rjSj+Uo3t1Ziq0+NarDa4gxogWrYPsIhaT7XdrgYibKYP32IdL8XmvCm+qANEXOrD1u+BnOUgYd62Bwb2u27WuBvOUkgybfT3p7EFJftUhkxF21Ckt/haoDeh+ZllFxox0GfyGH3waYiI6LZut0htO6waWCY0NEcFdZG2gPOl3nf7FlVFNoyJibgbDvcji8aTHbCpfD8o1EsT1TAwmESp6RVmn4c7Yo6Gf01e2Eo+2XFczkhChHZMxTcsdErCdcqnh0w9mVfoV8uqY9v6BBVUIZ0BuskbyW8h2VV1Jfi9sKop58G9XV+f2lDNf5yUemrBbVsAOrHx6jOrmDUnQx7LSoeMcbPInPXNC/aeePbGheiCSNmezIulg8fkDOuKde7O+KOO7g1JqCWI8Cqw9gv+nri/7W12vLgn0kd5h0hfyTgD+HTshzZKMHBqWM3HCQWLLS0GG4TPFxH+AHk5kSJHN2BkoOV970KS4B2MO4ExbaZEXmRSlnpqA8yEciaJbwVlB74s63zM75co2/meeoNOjI6P/4wHCdcRycxa2cFSieJoA7h6J6wqc0xFPCtmeFtCvALZb5rdB6YYy0xirjeXVJG1tL88yMHjCeGAt3JEINu7WsAqBnUNdT7VsROnlJQSWf4dEwg+KKCTzvHDUAfrCeUHipPmJGQkkgkIZYcwE8hYlErw96FRlZK4dZmCqkY8QWnkAOS5mdzwv0LZS4VYKM5PDH+FrskhYFsfQQ6pFvtqzzVQ3h9QLAnLd2sTunMcrr715gz0mwJdTVdpSbGPcGL5vJTkoZsS5bHCikF+HT6ZmY40K4PIBfI12549ci6BVdHdsW0viXk/Qz8pw9MjKkO4eGwHyjGQ3arQpAwYeRUbW2fRTjvxgbU8/1XYarQUg5mGAO0btwVCHzZv28AW2UzAzPSNj5bDgrEe3arnudtEMCchHOPXp2CR/kYtv7FzMQHQDGb0X/JoIIBr+7sZmW4ZTVSPnwrbHvpmUOw9/eCjYol/jwp8OUW3yk3aNxNBISMS3Gb1xtbBWbVrg232iz732vb5P6rK2LXd38g60D3/Bb9si3TYf8SXBGhEW0yFE36M4e49AtRH6cys3P+zv+1bzCgc14D9wRvkdZJcMHDrQUgeWU2ue2+ERLMra2IJ9LK159CCaWUnTVnNFAFvexU43fE+SUCv26R1kBgrNKg6PaL0Snlf3kmO/lhmfLXAs9MsPY82EyYs8Hg6CpaAg36BYOB0zrFUdW0eDZ3+O+fraYbWBhi6hb6NGTyWdEXT18VjvAL6R66Gpt0i8QOv94Tf6Ijr+FkW3c2bv7e5QnOUMhZ2hfd/JhBNob0RumzUnzg7ru3482qLo86oBEh8y9E0ml8BPP+3vPw95Bp3JxOXXzSf0cGqnamzpMRxP2JDaoqO+1inlTZBLUTH42qSXN2784MbfS+mmf0ejRkG/XS+KNpIHQ6Kh/g4dyAmwO22/wfOCwPpFGYetdZvGSGI6WcnX9X42eqporcKe3K82a8Y5y+3rfm++QIW6/83BwtspFtdQS08sFppLmzT1O3YMcfx8LpS6a4p29MEYL17gBAbljqq5AyeXoyBpEagBjWWvf77BwhvrriNjS6JHsD2YFPA7zGs7U3IvEtKOFbG1IhsTaiys5lNL2CvIYq3XaD7Vj8kA+NNl3gQaPjnc9fCee7vEXXAmQVMCxzBArGkgvj1FMAbX1qGdpuu2wthHsu37be/EBRC/mAbSoT1z4pI1+I7K2vAdQbgabrg9D6RZVD73gkX6Ih5a0Jf/Qa0oXRRynEElx8LJeF6oaB8qFmRsnJbd3JBoX6XOwuDgXEKXZubVfZn/E2I08RlQQdbq2m2tH5J1Siabsv7Bud3OeGxfB2hi7YdoVZreEHX0LaLEEMht5fHBed8BfDstCpqx+/ErNvFGj4co0mYlGvzXHcF6GAseR6Z4Abq+FNTeqkiA+hxOoqOpEZJijNDDNFTHTv+k9eAGZWzNFQrVTTylKSpCf41uWrpPWxqXbl2vbxhEi26Z0Tj32fUBYy3DqT2wVqCbbrBnoYy6Op62bSlPqb+D1KlY0+TtvG5oiM34KHOqtsiCYbWUjTZ9eCnMOGHGPWhYoJ6xU5oyaweSUUjmBTk5EyxSBctM/bqaM7o9NRsNhERF2HDriX/Idl3PtgkiCSR81Z+aNLXr+DAN2BgQyiaM8P1qeHcLPR0/Db/sV7o7aPSckt8ioqtdrgJj8rLDaHw+nH2huYKTknUK7to8bwz0O8oNELoFwtBq9BZsSujaS3TOJLgiYygTSXwcpFeZ7W0PeV781e0Bfm+41gX7NuTQhN1eRT0cPL0/Jj30Nphd9gMVYrWnNmkiXQqgiERk0VHaF9Vmg0HZ3lWqnYSuX2bryF472vUcuAPbOtyN9UN1Ny0C7R4D/B9qjnpeBP3T0CO8BumhcLNFwN9HjxZOouvhJK9ONXTyIZRCjEaxOak4A6NG7v8z0zz5dHH87vfT9Pj8LL04vTz/+OHyNHnBoJ8HeHumuilb3THw31AlDAfHaMStN/RoCEIzj4H/yNGlfOuco0+XrSnHbqTRFUPdXxrHq05mDM41B8ziThDSvX4kMS5QIhs2ih0HGHWg9LItOnWt3Lez1Jwlyst4AdOdwA211t/MA3NTfohQ7QXGQV3egZJB/v2y22rDU9e/0N0oOXSXzThc/yrbkKHZOID7YqYHcB1eqXfJJdn4tnulHbCN8Xs0bKgHcNkyktrN/ykVaOy0Ur7k9/7M56tXrz6W2C6B2AL/EYESJ1BLdznqtWlo6n/gAr7HivUUOywlq58qNzJh7g7jj3F6ynbA9UWT5rbI527gb8bOub2Mo12KyzaUqea0lRvs5thtmBsdp0QCtDy/RS8j6Nqzbt2Y/EGHTT97lbV28qYxZbxbOFiNV+Mw3XmCTQjbtf1XNKQAP43NHa8dZO8QR5Xm/0phkktzcYcwxxniHACv2QL4jJVQo0UYuhhF+tW/MexNHHGqT7WTdIdBky68FMilFyqbrnmv8T1lfauXkJThXXn8G+8SrJr3XuNgCSyX6z/ewce/vjmY0pwKBZo0DB+pCvGmrs7xYF79jMaMzzA3LUV9TCVX72nYm4iAdMOFNPvPn/v9XXdy09nW9OjcEkTBfNOjkc/oOIXsfcyzE2QB7NbHOXbsCGmQDGlu6JDyLiE2n5PwP7D4u16jPlakaGzc6iApcHoKIlL9/tSAv4m1BqgynGilT61dSKYOTLdvgF1RZRE1w99ju3i6eRg08lPw5W3GmZ5mpkH4wwCzXcOuJGskXrWyJwD/gDcSMCnRIyN6B3f7Uvj3MbbBxtt7KXYt+Br34HWqsUtpdIvA6+wbtyA7cvB1GyzzzyIzO/TAe7wYbh+4EW7yTYZNO7aCvGvZ+j1zhM5t4RWNg+u2K9oH/4qyfm3oAjbQG5Yu0a04PMlGyvwRsN+jf9IJwFaFrj7Q7JSiiYL+Rdt2UAss6BjbiLR7glexQb+K6t5ewZ6y4Kn6R+GebOJM8NIdoKBNZhccPnm3rgXVCLqkeB4kcYu/qc1Aemo1NjPFDHvNgi53QnTSddv9Klrk7sRwVS3QfGpQbVf8ePoaREYcjpj9V15m1RMJYQQnE/zEt9gkpP5GnfsJ/ctbQ4BM+Dl28eeU/adY31ZcZme2tjoZaip5CJhJlz/trlb8otZPf+ZFrfCWlr4u7eoC8Plekba317fsP1XTCvId5gnFOkKWXVLQ/wXB4U5C'}, 'MEM': {'sha256': '8efd02869237d0d9e960706912b2f994f58d3012414b2478c8ef187421781ce2', 'z64': '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'}, 'BIND': {'sha256': '8e19fa3e9e95963152fb689ee526b5d4a564eeb1d2c2233f792f1609ac7d6c4f', 'z64': 'eNplU0uP2yAQvu+vmBu2hLJtpfYQiUpd9aFeWinSnqJoRcw4oSHgAt7d7Gr/eweM7aTBFzMM8z1m0MfO+Qh7GfZGb/mf4OzNjcIWLKKq3IE/7U/18gZoaQq6CO6w9FIHhFVvoz7iN++dr1LacLFxNqKND0HvrIy9x8rIE/pQqnikmB0BF2EvP3z8VCXcheqPXajWlV8zpXcYIttw+g/6BdmmhtZ58KAtDPU2PGAnvYzOB1ExTt+S1fUCbeMUVvS3x+ehTjVS22NzeNhqq7TdVUS01TuOzx02ERV/lF5LGzkd43Nhm10oBwm6Ys7rnbbSEFzbG8NqkFaBQVvqrZlxT0SPGAuRwmP9+vM7zlbOxTZAaFyHoHTbpsy6GNMG8fqWbC6AQsxogIYsfyU7svqvxZ+ln23JvNfMY2d0I4nA29i2uV6mvMyqSvojMdDOso0Q77OUEg9RRkxRKijViU0yE88i7Qqx5sB+2kdptLpVfY5GhAQ6lC1SE2XZxF4a/kS8MIHCi+6uLJyaU9oxtWS4Pc+JEEOhOZL5jmnDCM1Jw56zL/kcMtw4uLfOK9pdNufKyKkxyzM+ix3GivVbGgod4JezyNnvkgg/euIFvR0lmRP0AQPc351hpC7PUstYoKeZRpGMzwj/S60vLmQ+061EJL3aRCZbMp2smTQkfIWdC5oe0ek77beyOZB3dIl2Ac9MnLUJMdXgF8h5sRX+7bWnnt7fQXlqo5lAfe/QH3UM0I5o9T8oToGe'}}

def need(ok,why):
    if not ok:raise RuntimeError(why)


def digest(raw):return hashlib.sha256(raw).hexdigest()


def wire(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


def atomic(path,value):
    path=Path(path);tmp=path.with_name(path.name+'.next')
    fd=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as out:out.write(wire(value));out.flush();os.fsync(out.fileno())
    os.replace(tmp,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def read(path,limit=8*1024**2):
    path=Path(path);need(path.resolve(strict=True)==path,'Redirected input')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as src:
        st=os.fstat(src.fileno());need(stat.S_ISREG(st.st_mode) and st.st_uid in (0,1204) and st.st_size<=limit,'Input type/owner/size differs')
        raw=src.read(limit+1);need(len(raw)<=limit,'Input grew beyond bound');return raw


def load_module(name,raw):
    m=types.ModuleType(name);m.__file__=str(BASE/'entry.py') if name=='services' else '<embedded-'+name+'>'
    sys.modules[name]=m;exec(compile(raw,m.__file__,'exec'),m.__dict__);return m


def run(argv,timeout=15):
    p=subprocess.run(list(map(str,argv)),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout)
    if p.returncode!=0:
        COMMAND_FAILURES.append({'command':Path(str(argv[0])).name,'exitCode':p.returncode,
            'stdout':p.stdout[:8192].decode(errors='replace'),'stderr':p.stderr[:8192].decode(errors='replace')})
    need(p.returncode==0,'Bounded command failed: '+Path(str(argv[0])).name+' exit '+str(p.returncode))
    return p.stdout.decode()


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self,path,timeout):super().__init__('localhost',timeout=timeout);self.path=path
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);self.sock.settimeout(self.timeout);self.sock.connect(str(self.path))


class Api:
    def __init__(self,ctx):self.ctx=ctx
    def call(self,method,path,body=None,timeout=30):
        need((method=='GET' and (path=='/v2/sandboxes?limit=1' or re.fullmatch('/sandboxes/[A-Za-z0-9_-]+',path))) or
             (method=='POST' and path=='/v2/sandboxes') or
             (method=='DELETE' and re.fullmatch('/sandboxes/[A-Za-z0-9_-]+',path)),'Route outside experiment')
        self.ctx.guard();c=UnixHTTP(self.ctx.active/'api.sock',timeout)
        try:
            c.request(method,path,None if body is None else wire(body),{'X-API-Key':self.ctx.key,'Content-Type':'application/json'})
            r=c.getresponse();raw=r.read(2*1024**2+1);need(len(raw)<=2*1024**2,'API result exceeds bound')
            if method in ('POST','DELETE'):
                # Record the actual HTTP outcome before JSON decoding or engine
                # validation can fail. Never persist returned access tokens.
                preview=None
                if not 200<=r.status<300:
                    preview=self.ctx.transport.redact(raw[:32768],[self.ctx.key]).decode(errors='replace')
                    preview=re.sub(r'(?i)(["\']?[\w-]*(?:token|secret|password)["\']?\s*[:=]\s*)["\'][^"\']*["\']',r'\1"[REDACTED]"',preview)
                evidence={'method':method,'route':path,'httpStatus':r.status,'responseBytes':len(raw),'responseSha256':digest(raw),
                    'errorPreview':preview,'previewTruncated':len(raw)>32768,'receivedUnixNs':time.time_ns()}
                fd=os.open(self.ctx.work/'http-outcomes.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'ab') as out:out.write(wire(evidence)+b'\n');out.flush();os.fsync(out.fileno())
            value=json.loads(raw) if raw else None
            return r.status,value
        finally:c.close()


def compact_native(rows):
    packed=[]
    for original in rows:
        row=dict(original);values=row.pop('records')
        need(all(isinstance(x,list) and len(x)==5 and x[4]==0 and x[3]>=x[2] for x in values),'Native request/batch record failed')
        elapsed=sorted(x[3]-x[2] for x in values);span=row['endNs']-row['startNs'];need(span>0,'Native timer span invalid')
        row.update(recordCount=len(values),rawRecordsRetainedOnNode=True,throughputMiBPerSecond=row['actualBytes']*1e9/span/1024**2)
        if row['mode']=='ram-dep':row['meanDependentLoadNs']=span/row['operations']
        if row['mode']=='ram-copy':row['copyPayloadMiBPerSecond']=row['throughputMiBPerSecond']/2
        if elapsed:row['batchOrReadElapsedNs']={name:elapsed[min(len(elapsed)-1,int((len(elapsed)-1)*q))] for name,q in [('p50',.5),('p95',.95),('p99',.99)]}
        packed.append(row)
    return packed

class Context:
    def guard(self):
        need(self.service.identity()==self.expected['identity'],'Identity changed')
        for label in ('runtime','sdk','view'):self.app.bound(label)
        self.app.candidate_live()
        need(self.app.bound('runtime')==self.runtime and digest(read(BASE/'public/rootfs-index.json'))==self.expected['indexSha256'],'Runtime/index changed')
        if self.permission_error:raise RuntimeError(self.permission_error)

    def event(self,kind,data):
        value={'runId':RUN,'node':self.node,'identity':self.expected['identity'],'entrySha256':self.pin,'kind':kind,'data':data}
        raw=wire(value);atomic(self.work/(kind+'.json'),value)
        print('PHASE='+self.node+':'+kind,flush=True)
        key='four-guest/'+SESSION+'/'+RUN+'/'+self.node+'/'+kind+'.json'
        # Retry only idempotent receipt publication, never the underlying action.
        for attempt in range(4):
            try:
                self.results.immutable_result(RESULTS,1438089386,'main',key,raw);return value
            except self.transport.Network as error:
                if error.status not in (409,422):raise
                code,old,_=self.results.contents(RESULTS,key,'main')
                if code==200:need(old==raw,'Conflicting immutable receipt');return value
                if attempt==3:raise
                time.sleep(2+attempt)

    def peer_event(self,kind,seconds=900):
        deadline=time.monotonic()+seconds
        while True:
            self.guard()
            for name in ('failed',kind):
                key='four-guest/'+SESSION+'/'+RUN+'/'+self.peer+'/'+name+'.json'
                code,raw,_=self.results.contents(RESULTS,key,'main')
                need(code in (200,404),'Peer GitHub read failed')
                if code==200:
                    value=json.loads(raw);need(value['identity']==self.approval['nodes'][self.peer]['identity'] and value['entrySha256']==self.pin and
                        value['runId']==RUN and value['node']==self.peer and value['kind']==name,'Peer receipt identity differs')
                    need(name!='failed','Peer stopped; no workload advancement');return value['data']
            need(time.monotonic()<deadline,'Peer barrier timed out; preserve owned Guests')
            print('WAIT_PEER='+self.peer+':'+kind,flush=True)
            time.sleep(10)

    def owner_permissions(self):
        try:
            while not self.stop.wait(.1):
                self.guard()
                self.no_foreign_jwk_daemon()
                if self.case is None or not any(x.get('kind')=='create' for x in self.case.state['openRequests']):continue
                for path in Path('/dev').glob('ublk[bc]*'):
                    if not re.fullmatch('ublk[bc][0-9]+',path.name):continue
                    meta=path.lstat();key=(meta.st_ino,meta.st_rdev)
                    if path.name in self.before_devices:continue
                    with self.lock:
                        if any(row['path']==str(path) and tuple(row['identity'])==key for row in self.permissions):continue
                    fd=os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
                    try:
                        now=os.fstat(fd)
                        if (now.st_ino,now.st_rdev)!=key or not (stat.S_ISBLK(now.st_mode) or stat.S_ISCHR(now.st_mode)):continue
                        check=subprocess.run([str(self.helper),path.name],capture_output=True,timeout=3)
                        if check.returncode!=0:continue  # Unknown/other owner: never grant.
                        need(check.stdout.strip()==b'1204:1205','Unexpected kernel ownership reply')
                        need((path.stat().st_ino,path.stat().st_rdev)==key,'Device replaced during ownership check')
                        target=f'/proc/{os.getpid()}/fd/{fd}'
                        prior=run(['getfacl','-cpn',target])
                        row={'path':str(path),'identity':list(key),'priorAcl':prior,'state':'grant_intent'}
                        with self.lock:self.permissions.append(row);atomic(self.work/'device-acls.json',self.permissions)
                        run(['setfacl','-m','u:1204:rw',target]);row['state']='granted'
                        with self.lock:atomic(self.work/'device-acls.json',self.permissions)
                    finally:os.close(fd)
        except BaseException as error:self.permission_error='New-device permission guard stopped: '+type(error).__name__;self.stop.set()

    def process_row(self,pid,role):
        ident=MEM.identity(pid);p=Path('/proc')/str(pid);st=(p/'exe').stat()
        need(len(set(ident['uids']))==1 and ident['uids'][0] in (0,1204),'Unexpected process owner')
        return {'pid':pid,'startTicks':ident['startTicks'],'uid':ident['uids'][0],'role':role,
                'executable':os.readlink(p/'exe'),'exeDev':st.st_dev,'exeInode':st.st_ino}

    def observe(self):
        self.guard();expected={j['sandboxId']:j for j in self.jobs};found={};runtime_cg=Path('/proc',str(self.pid),'cgroup').read_text()
        fcmeta=Path(self.app.plan['binaries']['deps/firecracker/1.15.1-patch-v3/firecracker']['path']).stat()
        for proc in Path('/proc').iterdir():
            if not proc.name.isdigit():continue
            try:
                if (proc/'cgroup').read_text()!=runtime_cg:continue
                st=(proc/'exe').stat()
                if (st.st_dev,st.st_ino)!=(fcmeta.st_dev,fcmeta.st_ino):continue
                err=Path(os.readlink(proc/'fd/2'));sid=err.parent.name
                need(sid in expected and sid not in found and err.name=='firecracker-stderr.log','Unexpected FC in owned Runtime')
                cwd=(proc/'cwd').resolve();need(cwd.parent==self.active/'fc' and cwd.name.startswith('agentenv-fc-'),'FC directory differs')
                raw=read(cwd/'overlaybd/image.json');config=json.loads(raw)
                BIND.check_binding(config,self.template['rootfsLayers'],'full',self.index)
                row={'sandboxId':sid,'process':self.process_row(int(proc.name),'fc'),'cwd':str(cwd),'configSha256':digest(raw),'upper':[],'devices':[]}
                for key in ('data','index'):
                    p=Path(config['upper'][key]);p=p if p.is_absolute() else cwd/'overlaybd'/p
                    need(p.resolve()==p and p.is_relative_to(cwd),'Upper escaped Guest directory');m=p.stat()
                    need(m.st_uid==1204 and m.st_nlink==1 and stat.S_ISREG(m.st_mode),'Upper ownership/type differs')
                    row['upper'].append({'path':str(p),'category':'private-upper','identity':MEM.immutable_identity(m),'immutable':False})
                for fd in (proc/'fd').iterdir():
                    try:
                        m=fd.stat()
                        if not stat.S_ISBLK(m.st_mode):continue
                        target=Path(os.readlink(fd))
                        if not re.fullmatch('/dev/ublkb[0-9]+',str(target)):continue
                        h=os.open(target,os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
                        try:size=struct.unpack('=Q',fcntl.ioctl(h,0x80081272,b'\0'*8))[0]
                        finally:os.close(h)
                        row['devices'].append({'path':str(target),'inode':m.st_ino,'major':os.major(m.st_rdev),'minor':os.minor(m.st_rdev),'bytes':size,
                            'maxSectorsKiB':int(Path('/sys/class/block',target.name,'queue/max_sectors_kb').read_text())})
                    except FileNotFoundError:continue
                rootdev=(cwd/'user-rootfs').resolve()
                need(any(d['path']==str(rootdev) for d in row['devices']),'FC lacks declared rootfs device')
                need(all(d['maxSectorsKiB']==256 for d in row['devices']),'Actual rootfs/memory I/O limits differ from 256KiB')
                row['rootfsDevice']=str(rootdev);found[sid]=row
            except (FileNotFoundError,ProcessLookupError):continue
        need(set(found)==set(expected),'Not every confirmed Guest has an actual FC/DAX binding')
        upper=[(x['identity']['dev'],x['identity']['inode']) for r in found.values() for x in r['upper']]
        need(len(set(upper))==4,'Private upper aliases across Guests')
        return found

    def file_sample(self,row):
        try:
            fd=os.open(row['path'],os.O_RDONLY|os.O_NONBLOCK|os.O_NOFOLLOW)
            try:FSDAX.validate_fd(fd,os.fstat(fd).st_size,fs_dax=False)
            finally:os.close(fd)
            return MEM.file_sample(row,Path('/home/jwk/agent'),os.sysconf('SC_PAGESIZE'))
        except (OSError,ValueError,TimeoutError) as error:return {'path':row['path'],'category':row['category'],'residentBytes':None,'errorType':type(error).__name__}

    def dax_evidence(self):
        view=self.app.state['steps']['view']['result']['journal'];broker=view['rootfsBroker'];pid=broker['pid']
        # The root view process remains bound; also freeze its broker child identity.
        need(MEM.identity(pid)==self.broker_identity,'DAX broker changed')
        values=[]
        for item in broker['inheritedFiles']:
            fd=os.open(f'/proc/{pid}/fd/{item["fd"]}',os.O_RDONLY|os.O_CLOEXEC)
            try:values.append({'layerDigest':item['replica']['layerDigest'],**FSDAX.validate_fd(fd,item['replica']['fileBytes'])})
            finally:os.close(fd)
        return {'files':values,'ordinaryFileDataPageCacheApplicable':False,'mincoreUsed':False,'publication':view['publication']}

    def collect(self,include_files=False):
        self.guard();begin=time.monotonic_ns()
        values={'node':self.node,'unixNs':time.time_ns(),'beginNs':begin,'hostMemoryBytes':MEM.kib_fields(Path('/proc/meminfo').read_text()),
                'processes':[MEM.process_sample(p) for p in self.processes],'ordinaryFiles':None,'blockDevices':None,
                'uniqueLogicalUbBytes':1900019712,'incrementalPhysicalUbBytes':None,'netSavingsBytes':None,
                'GuestRamOnlyBytes':None,'samplingAtomicAcrossNodes':False,'cacheDropPerformed':False}
        if include_files:
            values['ordinaryFiles']=[self.file_sample(row) for row in self.files]
            values['blockDevices']=[]
            for row in self.devices:
                try:values['blockDevices'].append(MEM.device_sample(row,os.sysconf('SC_PAGESIZE')))
                except (OSError,ValueError,TimeoutError) as e:values['blockDevices'].append({'path':row['path'],'residentBytes':None,'errorType':type(e).__name__})
            values['dax']=self.dax_evidence()
        values['endNs']=time.monotonic_ns();return values

    def launcher(self,argv,**kwargs):
        self.guard();return subprocess.Popen(['nsenter','-t',str(self.pid),'-n','--',*argv],**kwargs)

    def failure_details(self):
        """Read current failures into this archive, without another user round."""
        now=int(time.time());begin=now-900
        p=self.work/'cohort.json'
        if p.exists():
            state=json.loads(read(p))
            stamps=[r['startedNs']/1e9 for r in state.get('openRequests',[])]
            if stamps:begin=max(now-1800,int(min(stamps))-10)
        proc=subprocess.run(['journalctl','--no-pager','-q','-u',self.runtime['name'],'--since','@'+str(begin),
            '-n','500','-o','short-precise'],stdin=subprocess.DEVNULL,capture_output=True,timeout=20)
        def redact(raw):
            text=self.transport.redact(raw,[self.key]).decode(errors='replace')
            return re.sub(r'(?i)(["\']?[\w-]*(?:token|secret|password)["\']?\s*[:=]\s*)["\'][^"\']*["\']',r'\1"[REDACTED]"',text)
        atomic(self.work/'runtime-failure-details.json',{'exitCode':proc.returncode,
            'runtimeJournal':redact(proc.stdout[-384*1024:]),'journalTruncated':len(proc.stdout)>384*1024,
            'stderr':redact(proc.stderr[:8192]),'commandFailures':[
                dict(row,stdout=redact(row['stdout'].encode()),stderr=redact(row['stderr'].encode())) for row in COMMAND_FAILURES[-8:]],
            'servicesChanged':False,'createRetried':False})


    def __init__(self):
        need(os.geteuid()==0,'Use approved unified root entry');self.node={'server1':'node-a','agent1':'node-b'}.get(socket.gethostname());need(self.node,'Only A/B')
        self.n=self.node[-1];self.peer='node-b' if self.n=='a' else 'node-a';self.pin=digest(read(Path(__file__),256*1024))
        original=Path('/home/jwk/root/relay/jobs')/('titanic-dax-services-20261102-013-'+self.node)/'task.py';raw=read(original,256*1024);need(digest(raw)==SERVICE_PIN,'Original deployed source differs')
        self.service=load_module('services',raw);self.service.__file__=str(original);self.transport=self.service.module('api')
        creds=Path('/home/jwk/.local/state/agentenv-github-relay/credentials.json');need(not creds.stat().st_mode&0o077,'Credentials permissions differ');tokens=json.loads(read(creds,8192))
        self.control=self.transport.GitHub(tokens['controlToken']);self.results=self.transport.GitHub(tokens['resultToken']);self.control.private_repo(CONTROL,1438089258);self.results.private_repo(RESULTS,1438089386)
        code,raw,_=self.control.contents(CONTROL,SPEC,'main');need(code==200 and digest(raw)==CONTRACT_SHA,'Frozen private experiment contract missing or changed');self.approval=json.loads(raw)
        need(self.approval['humanApproved'] and self.approval['entrySha256']==self.pin and self.approval['runId']==RUN,'Specific contract/source differs')
        self.expected=self.approval['nodes'][self.node];need(self.service.identity()==self.expected['identity'],'Node boot changed')
        self.app=self.service.Start(self.node,self.transport,self.results,'status');sys.path.insert(0,str(BASE/'code'))
        global FSDAX
        from aenv_ub_provider import fsdax
        FSDAX=fsdax
        self.runtime=self.app.bound('runtime');self.pid=self.runtime['pid'];self.active=self.app.active
        need(self.runtime==self.expected['runtime'] and self.app.state['phase']=='services_ready_held','Deployed healthy Runtime differs')
        HOME.mkdir(mode=0o700,exist_ok=True);self.work=HOME/self.node;self.work.mkdir(mode=0o700,exist_ok=False)
        for x in (HOME,self.work):need(x.resolve()==x and x.stat().st_uid==0 and not x.stat().st_mode&0o077,'Unsafe measurement root')
        self.lockfd=os.open(BASE/'private/titanic-measure.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(self.lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        self.key=tomllib.loads(read(self.active/'cli/aenv/credentials').decode())['api_key'];self.api=Api(self);self.case=None;self.jobs=[];self.bindings={};self.processes=[];self.devices=[]
        self.lock=threading.RLock();self.permissions=[];self.permission_error=None;self.stop=threading.Event();self.files=[];self.file_keys=set()
        self.helper=Path('/home/jwk/root/t1-locality-v1/public/ublk_owner');need(digest(read(self.helper,1024**2))==OWNER_PIN and self.helper.stat().st_uid==0 and not self.helper.stat().st_mode&0o022,'Existing kernel owner query differs; never compile')
        self.probe=Path('/home/jwk/agent/r')/('t1-probe-'+self.n+'-v1/probe');self.probe_raw=read(self.probe,1024**2);need(digest(self.probe_raw)==PROBE_PIN,'Existing native Guest probe differs; do not download/build')
        self.before_devices={x.name:(x.lstat().st_ino,x.lstat().st_rdev) for x in Path('/dev').glob('ublk[bc]*')}
        self.old_daemons={}
        for x in Path('/proc').iterdir():
            if not x.name.isdigit():continue
            try:
                if 'uvm-ublk' in (x/'comm').read_text() and MEM.identity(int(x.name))['uids']==[1204]*4:self.old_daemons[int(x.name)]={'identity':MEM.identity(int(x.name)),'cgroup':(x/'cgroup').read_text()}
            except (FileNotFoundError,ProcessLookupError):continue
        atomic(self.work/'preexisting-daemons-readonly.json',self.old_daemons)
        self.indexraw=read(BASE/'public/rootfs-index.json');need(digest(self.indexraw)==self.expected['indexSha256'],'Strict index differs');self.index=json.loads(self.indexraw)
        self.template=self.approval['template'];self.steps=self.approval['steps']
        need(len(self.steps)==9 and sum(x['delay'] for x in self.steps)==50 and self.template['resources']=={'cpu_count':2,'memory_mib':4096,'disk_size_mib':65536},'Original Titanic actions/resources differ')
        need(digest(read(self.app.work/'seed/repository/catalog/records'/(self.template['templateId']+'.json')))==self.template['catalogSha256'],'Captured catalog differs')
        self.env={'HOME':'/home/jwk','USER':'jwk','LOGNAME':'jwk','LANG':'C.UTF-8','PATH':'/usr/sbin:/usr/bin:/sbin:/bin','XDG_CONFIG_HOME':str(self.active/'cli'),'LD_LIBRARY_PATH':str(Path(self.app.plan['sourceDeployment'])/'native/lib')+':'+str(Path(self.app.plan['sourceDeployment'])/'native/fallback/lib')}
        self.broker_identity=MEM.identity(self.app.state['steps']['view']['result']['journal']['rootfsBroker']['pid'])
        for role,pid in [('runtime',self.pid),('collector',os.getpid()),('dax-broker',self.broker_identity['pid']),('sdk',self.app.bound('sdk')['pid']),('view',self.app.bound('view')['pid'])]:self.processes.append(self.process_row(pid,role))
        for layer in self.template['rootfsLayers']:
            self.add_file(Path(layer['file']),'rootfs-lower-source',True,optional=self.n=='b')
        for rel in self.approval['memoryPaths']:self.add_file(self.app.work/'seed/repository'/rel,'memory-lower',True)
        if self.n=='a':self.add_file(Path(self.app.plan['image']['path']),'full-source-image',True)
        for directory,category in [(Path('/home/jwk/agent/dsbench-20261031/oci-blobs'),'prepared-oci-blob')]:
            if directory.exists():
                rows=[x for x in directory.iterdir() if x.is_file() and not x.is_symlink() and not x.name.endswith(('.lock','.partial'))];need(len(rows)<=64,'Source file count exceeds scope')
                for x in rows:self.add_file(x,category,True)
        self.guard();self.dax_evidence()

    def no_foreign_jwk_daemon(self):
        cg=Path('/proc',str(self.pid),'cgroup').read_text()
        for p in Path('/proc').iterdir():
            if not p.name.isdigit():continue
            try:
                if 'uvm-ublk' not in (p/'comm').read_text():continue
                ident=MEM.identity(int(p.name))
                if ident['uids']!=[1204]*4 or (p/'cgroup').read_text()==cg:continue
                before=self.old_daemons.get(int(p.name));need(before and before['identity']==ident and before['cgroup']==(p/'cgroup').read_text(),'New/changed unrelated jwk daemon; ACL worker stops')
            except (FileNotFoundError,ProcessLookupError):continue

    def add_file(self,path,category,immutable,optional=False):
        if not path.exists():
            need(optional,'Missing required file '+str(path));return
        need(path.resolve()==path,'Sample file redirected');s=path.stat();need(stat.S_ISREG(s.st_mode) and s.st_uid==1204,'Unexpected sampled file owner/type')
        key=(s.st_dev,s.st_ino)
        if key in self.file_keys:return
        self.file_keys.add(key);self.files.append({'path':str(path),'category':category,'identity':MEM.immutable_identity(s),'immutable':immutable})

    def backend_io(self):
        need(MEM.identity(self.broker_identity['pid'])==self.broker_identity,'Broker identity changed')
        return dict((k,int(v.strip())) for k,v in (x.split(':',1) for x in Path('/proc',str(self.broker_identity['pid']),'io').read_text().splitlines()))

    def run_stage(self,name,steps):
        target=self.work/name;target.mkdir(mode=0o700,exist_ok=False);before=self.backend_io()
        jobs=[dict(j,steps=steps) for j in self.jobs]
        report=GROUP.NativeGroupReplay(target,self.active/'aenv-host-dax',self.env,jobs,REPLAY.shell_command,self.case.owned,self.collect,lambda value:atomic(target/'replay.json',value),launcher=self.launcher).run()
        atomic(target/'broker-io-window.json',{'before':before,'after':self.backend_io(),'attribution':'node window, not per Guest exact UB bytes'})
        need(report['status']=='LOCAL_REPLAY_COMPLETED_GUESTS_RETAINED' and report['pendingCommands']==0 and report['nonzeroCommands']==0,'Stage failed; preserve exact request/command evidence without retry')
        return report

    def probe_records(self,name,mode):
        rows=[]
        for slot in (0,1):
            text=read(self.work/name/'commands'/f'{slot}-0.stdout',4*1024**2).decode();values=[]
            for line in text.splitlines():
                if line.startswith('{'):
                    try:row=json.loads(line)
                    except ValueError:continue
                    if row.get('mode')==mode:values.append(row)
            need(len(values)==1 and values[0]['state']=='completed','Missing completed native probe record');rows.append(values[0])
        atomic(self.work/(name+'-native.json'),rows);return rows

    def execute(self):
        need(self.api.call('GET','/v2/sandboxes?limit=1')==(200,[]),'This Titanic Runtime is not empty')
        atomic(self.work/'before-guests.json',self.collect(True));self.event('admitted',{'templateId':self.template['templateId'],'sharedObjectName':self.expected['sharedObjectName'],'replaySha256':self.template['replaySha256']})
        peer=self.peer_event('admitted');need(peer['templateId']==self.template['templateId'] and peer['sharedObjectName']==self.expected['sharedObjectName'] and peer['replaySha256']==self.template['replaySha256'],'Peer workload/backing differs')
        case_id=hashlib.sha256((RUN+self.node).encode()).hexdigest()[:32]
        self.case=ENGINE.Cohort(self.api,{'version':1,'phase':'prepared','sandboxIds':[],'openRequests':[],'outcomeUncertain':False},lambda state:atomic(self.work/'cohort.json',state),None,None,lambda _:need(MEM.kib_fields(Path('/proc/meminfo').read_text())['MemAvailable']>=6*1024**3,'Insufficient available Host RAM'),None,run_id=case_id,mutation_guard=self.guard)
        marker=self.active/'external-mutation-observed';need(not marker.exists(),'Prior external mutation preserved');atomic(marker,{'runId':RUN,'work':str(self.work),'pendingBeforeCreate':True})
        watcher=threading.Thread(target=self.owner_permissions,name='owned-new-device-acl');watcher.start()
        try:
            for slot in (0,1):
                sid=self.case.create('/v2/sandboxes',{'templateID':self.template['templateId'],'timeout':7200,'secure':True,'autoPause':False,'allow_internet_access':False,'metadata':{'cow_batch':case_id,'full_compare_batch':RUN,'slot':str(slot)}})
                self.jobs.append({'sandboxId':sid,'slot':slot,'templateId':self.template['templateId'],'replaySha256':self.template['replaySha256'],'catalogSha256':self.template['catalogSha256'],'lowerContentSha256':BIND.content_signature(self.template['rootfsLayers']),'resources':{'cpu_count':2,'memory_mib':4096},'snapshotResources':self.template['resources'],'steps':self.steps})
            self.bindings=self.observe();atomic(self.work/'bindings.json',self.bindings);self.stop.set();watcher.join(10);need(not watcher.is_alive(),'ACL worker did not exit');self.guard()
            devices={}
            for row in self.bindings.values():
                self.processes.append(row['process'])
                for u in row['upper']:self.add_file(Path(u['path']),u['category'],False)
                for d in row['devices']:devices[(d['major'],d['minor'])]=d
                for log in Path(row['cwd']).rglob('*.log'):
                    if log.is_file() and not log.is_symlink() and log.stat().st_uid==1204:self.add_file(log,'guest-log',False)
            self.devices=list(devices.values());cg=Path('/proc',str(self.pid),'cgroup').read_text();exe=Path(self.app.plan['binaries']['bin/uvm-ublk-daemon']['path']).stat()
            for proc in Path('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    s=(proc/'exe').stat()
                    if (s.st_dev,s.st_ino)==(exe.st_dev,exe.st_ino) and (proc/'cgroup').read_text()==cg:self.processes.append(self.process_row(int(proc.name),'daemon'))
                except (FileNotFoundError,ProcessLookupError):continue
            need(any(x['role']=='daemon' for x in self.processes),'Actual owned daemon not found')
            self.event('guests-ready',{'unixNs':time.time_ns(),'sandboxIds':[j['sandboxId'] for j in self.jobs]});peer=self.peer_event('guests-ready');local=json.loads(read(self.work/'guests-ready.json'))['data'];start=max(peer['unixNs'],local['unixNs'])/1e9+45;need(time.time()<start,'Missed coordinated window')
            while time.time()<start:self.guard();time.sleep(min(.5,max(0,start-time.time())))
            atomic(self.work/'replay-window.json',{'plannedUnixSeconds':start,'actualUnixNs':time.time_ns(),'crossNodeClockVerified':False})
            self.run_stage('business',self.steps);atomic(self.work/'business-frozen.json',self.collect(True));self.event('business-frozen',{'completedCommands':18,'nonzeroCommands':0});self.peer_event('business-frozen')
            self.performance()
            atomic(self.work/'retained-guests.json',{'sandboxIds':self.case.state['sandboxIds'],'openRequests':self.case.state['openRequests'],'ownedGuestsReleased':False,'backingHeld':True,'requestedLifetimeSeconds':7200,'automaticRenewal':False})
            self.event('completed',{'status':'TITANIC_BUSINESS_PREAD_RAM_COMPLETED_GUESTS_RETAINED','sandboxIds':self.case.state['sandboxIds'],'businessCommands':18,'RAMCasesPerGuest':12,'UBAllocationChanged':False,'oldServicesChanged':False})
            self.summary()
        finally:self.stop.set();watcher.join(10)

    def performance(self):
        # Business endpoint is frozen before all extra reads and RAM allocations.
        reads=[];broker=self.app.state['steps']['view']['result']['journal']['rootfsBroker']
        for item in broker['inheritedFiles']:
            fd=os.open(f'/proc/{broker["pid"]}/fd/{item["fd"]}',os.O_RDONLY|os.O_CLOEXEC)
            try:
                FSDAX.validate_fd(fd,item['replica']['fileBytes']);limit=min(4*1024**2,item['replica']['fileBytes'])
                for repeat in range(2):
                    for offset in range(0,limit,262144):
                        before=time.monotonic_ns();data=os.pread(fd,min(262144,limit-offset),offset);end=time.monotonic_ns();need(len(data)==min(262144,limit-offset),'Host DAX short read');reads.append({'digest':item['replica']['layerDigest'],'repeat':repeat,'offset':offset,'bytes':len(data),'elapsedNs':end-before})
            finally:os.close(fd)
        atomic(self.work/'host-dax-pread.json',{'reads':reads,'scope':'Host DAX pread includes buffer allocation/copy; not raw fabric bandwidth','physicalLocalRemoteConfirmed':False})
        root='/tmp/aenv-titanic-probe-v1';payload=base64.b64encode(self.probe_raw).decode()
        setup='umask 077; test ! -e '+root+' && /agentenv/bin/busybox mkdir '+root+' && printf %s '+shlex.quote(payload)+' | /agentenv/bin/busybox base64 -d > '+root+'/probe && test "$(/agentenv/bin/busybox sha256sum '+root+'/probe | /agentenv/bin/busybox cut -d \" \" -f 1)" = '+PROBE_PIN+' && /agentenv/bin/busybox chmod 700 '+root+'/probe && '+root+'/probe selftest '+root+'/selftest 0'
        self.run_stage('probe-setup',[{'action':setup,'delay':0}])
        discover="python -c "+shlex.quote("import glob,json,os,sys; p=sorted(set(os.path.realpath(x) for b in sys.path if b.startswith('/') for k in ('numpy','scipy','pandas','sklearn','numpy.libs','scipy.libs') for x in glob.glob(b+'/'+k+'/**/*.so*',recursive=True) if os.path.isfile(x)),key=lambda x:(-os.stat(x).st_size,x)); assert p and len(p)<4096; x=p[0]; print(json.dumps({'kind':'scientific-file','path':x,'bytes':os.stat(x).st_size}))")
        self.run_stage('scientific-file',[{'action':discover,'delay':0}]);found=[]
        for slot in (0,1):
            rows=[json.loads(x) for x in read(self.work/'scientific-file/commands'/f'{slot}-0.stdout').decode().splitlines() if x.startswith('{"kind": "scientific-file"')];need(len(rows)==1,'Scientific file not found');found.append(rows[0])
        need(found[0]==found[1] and found[0]['bytes']>=262144,'Local Guest scientific file differs');self.event('scientific-file',found[0]);need(self.peer_event('scientific-file')==found[0],'A/B scientific read file differs')
        for roundno in range(3):
            for label,mode in [('first','seq'),('repeat','seq'),('warm-random','rand')]:
                name='pread-'+label+'-r'+str(roundno);self.event(name+'-ready',{'mode':mode});self.peer_event(name+'-ready')
                action=root+'/probe '+mode+' '+shlex.quote(found[0]['path'])+' 262144 32 1';self.run_stage(name,[{'action':action,'delay':0}]);self.probe_records(name,mode)
        modes=('ram-dep','ram-read','ram-write','ram-copy')
        for roundno in range(3):
            for mode in modes[roundno:]+modes[:roundno]:
                name=mode+'-r'+str(roundno);self.event(name+'-ready',{'mode':mode});self.peer_event(name+'-ready');self.run_stage(name,[{'action':root+'/probe '+mode+' 30 256','delay':0}]);rows=self.probe_records(name,mode)
                need(all(x['workingSetBytes']==256*1024**2 for x in rows),'RAM working set differs')

    def summary(self):
        curves=[]
        for line in (self.work/'business/samples.jsonl').read_text().splitlines():
            r=json.loads(line);fc=[x['metricsBytes'] for x in r['processes'] if x['role']=='fc'];files={}
            for f in r.get('ordinaryFiles') or []:
                k=f['category'];v=f.get('residentBytes');files[k]=None if v is None or files.get(k,0) is None else files.get(k,0)+v
            curves.append({'unixNs':r['unixNs'],'hostCached':r['hostMemoryBytes'].get('Cached'),'hostBuffers':r['hostMemoryBytes'].get('Buffers'),'files':files or None,'fc':[{'rss':x['Rss'],'pss':x['Pss'],'anonPss':x.get('Pss_Anon'),'filePss':x.get('Pss_File')} for x in fc]})
        stages={}
        for f in self.work.glob('*-native.json'):stages[f.stem]=compact_native(json.loads(read(f,8*1024**2)))
        hashes=[]
        for f in self.work.rglob('*'):
            if f.is_file() and not f.is_symlink() and f.name not in ('experiment.lock',):hashes.append({'path':str(f.relative_to(self.work)),'bytes':f.stat().st_size,'sha256':digest(read(f,256*1024**2))})
        summary={'status':'TITANIC_BUSINESS_PREAD_RAM_COMPLETED_GUESTS_RETAINED','node':self.node,'templateId':self.template['templateId'],'sandboxIds':self.case.state['sandboxIds'],'businessCurve':curves,'businessBaseline':json.loads(read(self.work/'business/baseline.json')),'businessEndpoint':json.loads(read(self.work/'business-frozen.json')),'microbench':stages,'hostDaxPread':json.loads(read(self.work/'host-dax-pread.json')),'rawArtifacts':hashes,'rawArtifactsRemainOnNode':True,'physicalUbIncrementBytes':None,'netSavingsBytes':None,'newLogicalUbBytes':1900019712,'GuestRAMIsPrivateNotUB':True,'samplingAtomicAcrossNodes':False,'oldT1ServicesChanged':False,'ownedGuestsReleased':False,'GuestLifetimeSeconds':7200,'automaticRenewal':False}
        encoded=wire(summary);need(len(encoded)<768*1024,'Derived receipt too large; raw evidence stays on node');atomic(self.work/'derived-summary.json',summary);print(encoded.decode(),flush=True)


def main():
    global ENGINE,GROUP,MEM,REPLAY,BIND,CONTRACT_SHA
    need(len(sys.argv)==2 and re.fullmatch('[0-9a-f]{64}',sys.argv[1]),'Exact private contract SHA argument required');CONTRACT_SHA=sys.argv[1]
    for name,item in BUNDLED.items():
        raw=zlib.decompress(base64.b64decode(item['z64']));need(digest(raw)==item['sha256'],'Reused module differs');globals()[name]=load_module(name,raw)
    ctx=None
    try:ctx=Context();ctx.execute()
    except Exception as error:
        if ctx is not None:
            try:ctx.failure_details();ctx.event('failed',{'errorType':type(error).__name__,'reason':str(error)[:500],'backingHeld':True,'createRetried':False})
            except Exception:pass
            print(json.dumps({'status':'TITANIC_MEASUREMENT_FAILED_PRESERVE_GUESTS','errorType':type(error).__name__,'reason':str(error)[:500],'work':str(ctx.work),'cohort':json.loads(read(ctx.work/'cohort.json')) if (ctx.work/'cohort.json').exists() else None,'diagnosis':json.loads(read(ctx.work/'runtime-failure-details.json')) if (ctx.work/'runtime-failure-details.json').exists() else None}),flush=True)
        raise
if __name__=='__main__':main()
