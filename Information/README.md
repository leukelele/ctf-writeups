[Forensics](https://play.picoctf.org/practice/challenge/186?bookmarked=1&page=1)
> Files can always be changed in a secret way. Can you find the flag? cat.jpg

[cat.jpg](./cat.jpg)

# Writeup
My first thought was to run `strings` and `grep` to check if the flag was hidden as a printable string in the file.
```
$ strings cat.jpg | grep picoCtf

```

I couldn't find anything; admittedly, my CTF course did not delve deeply into the forensics side of CTFs, so at this point, I was somewhat stumped. I thought I found a hint in a [write-up](https://github.com/ctfs/write-ups-2014/tree/master/plaid-ctf-2014/doge-stege), not related to this problem, which made use of the tool `file`. This tool determines the file type.
```
$ file cat.jpg
cat.jpg: JPEG image data, JFIF standard 1.02, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 2560x1598, components 3
```

Another dead end. The image was confirmed to be a JPEG, which does not reveal any new information. `xxd`, however, reveals soemthing interesting:
```
$ xxd cat.jpg
00000000: ffd8 ffe0 0010 4a46 4946 0001 0200 0001  ......JFIF......
00000010: 0001 0000 ffed 0030 5068 6f74 6f73 686f  .......0Photosho
00000020: 7020 332e 3000 3842 494d 0404 0000 0000  p 3.0.8BIM......
00000030: 0013 1c02 7400 0750 6963 6f43 5446 1c02  ....t..PicoCTF..
00000040: 0000 0200 0400 ffe1 0bf9 6874 7470 3a2f  ..........http:/
00000050: 2f6e 732e 6164 6f62 652e 636f 6d2f 7861  /ns.adobe.com/xa
00000060: 702f 312e 302f 003c 3f78 7061 636b 6574  p/1.0/.<?xpacket
00000070: 2062 6567 696e 3d27 efbb bf27 2069 643d   begin='...' id=
00000080: 2757 354d 304d 7043 6568 6948 7a72 6553  'W5M0MpCehiHzreS
00000090: 7a4e 5463 7a6b 6339 6427 3f3e 0a3c 783a  zNTczkc9d'?>.<x:
000000a0: 786d 706d 6574 6120 786d 6c6e 733a 783d  xmpmeta xmlns:x=
000000b0: 2761 646f 6265 3a6e 733a 6d65 7461 2f27  'adobe:ns:meta/'
000000c0: 2078 3a78 6d70 746b 3d27 496d 6167 653a   x:xmptk='Image:
000000d0: 3a45 7869 6654 6f6f 6c20 3130 2e38 3027  :ExifTool 10.80'
000000e0: 3e0a 3c72 6466 3a52 4446 2078 6d6c 6e73  >.<rdf:RDF xmlns
000000f0: 3a72 6466 3d27 6874 7470 3a2f 2f77 7777  :rdf='http://www
00000100: 2e77 332e 6f72 672f 3139 3939 2f30 322f  .w3.org/1999/02/
00000110: 3232 2d72 6466 2d73 796e 7461 782d 6e73  22-rdf-syntax-ns
00000120: 2327 3e0a 0a20 3c72 6466 3a44 6573 6372  #'>.. <rdf:Descr
00000130: 6970 7469 6f6e 2072 6466 3a61 626f 7574  iption rdf:about
00000140: 3d27 270a 2020 786d 6c6e 733a 6363 3d27  =''.  xmlns:cc='
00000150: 6874 7470 3a2f 2f63 7265 6174 6976 6563  http://creativec
00000160: 6f6d 6d6f 6e73 2e6f 7267 2f6e 7323 273e  ommons.org/ns#'>
00000170: 0a20 203c 6363 3a6c 6963 656e 7365 2072  .  <cc:license r
00000180: 6466 3a72 6573 6f75 7263 653d 2763 476c  df:resource='cGl
00000190: 6a62 304e 5552 6e74 3061 4756 6662 544e  jb0NURnt0aGVfbTN
000001a0: 3059 5752 6864 4746 664d 584e 6662 5739  0YWRhdGFfMXNfbW9
000001b0: 6b61 575a 705a 5752 3927 2f3e 0a20 3c2f  kaWZpZWR9'/>. </
000001c0: 7264 663a 4465 7363 7269 7074 696f 6e3e  rdf:Description>
000001d0: 0a0a 203c 7264 663a 4465 7363 7269 7074  .. <rdf:Descript
000001e0: 696f 6e20 7264 663a 6162 6f75 743d 2727  ion rdf:about=''
000001f0: 0a20 2078 6d6c 6e73 3a64 633d 2768 7474  .  xmlns:dc='htt
00000200: 703a 2f2f 7075 726c 2e6f 7267 2f64 632f  p://purl.org/dc/
00000210: 656c 656d 656e 7473 2f31 2e31 2f27 3e0a  elements/1.1/'>.
00000220: 2020 3c64 633a 7269 6768 7473 3e0a 2020    <dc:rights>.  
00000230: 203c 7264 663a 416c 743e 0a20 2020 203c   <rdf:Alt>.    <
00000240: 7264 663a 6c69 2078 6d6c 3a6c 616e 673d  rdf:li xml:lang=
00000250: 2778 2d64 6566 6175 6c74 273e 5069 636f  'x-default'>Pico
00000260: 4354 463c 2f72 6466 3a6c 693e 0a20 2020  CTF</rdf:li>.   
00000270: 3c2f 7264 663a 416c 743e 0a20 203c 2f64  </rdf:Alt>.  </d
00000280: 633a 7269 6768 7473 3e0a 203c 2f72 6466  c:rights>. </rdf
00000290: 3a44 6573 6372 6970 7469 6f6e 3e0a 3c2f  :Description>.</
000002a0: 7264 663a 5244 463e 0a3c 2f78 3a78 6d70  rdf:RDF>.</x:xmp
000002b0: 6d65 7461 3e0a 2020 2020 2020 2020 2020  meta>.
000002c0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000002d0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000002e0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000002f0: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000300: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000310: 2020 2020 2020 2020 2020 0a20 2020 2020            .     
00000320: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000330: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000340: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000350: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000360: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000370: 2020 2020 2020 2020 2020 2020 2020 200a                 .
00000380: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000390: 2020 2020 2020 2020 2020 2020 2020 2020                  
000003a0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000003b0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000003c0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000003d0: 2020 2020 2020 2020 2020 2020 2020 2020                  
000003e0: 2020 2020 0a20 2020 2020 2020 2020 2020      .           
000003f0: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000400: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000410: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000420: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000430: 2020 2020 2020 2020 2020 2020 2020 2020                  
00000440: 2020 2020 2020 2020 200a 2020 2020 2020           .      
00000450: 2020 2020 2020 2020 2020 2020 2020 2020                  
...
```

Particularly these following sections:
```
...
00000070: 2062 6567 696e 3d27 efbb bf27 2069 643d   begin='...' id=
00000080: 2757 354d 304d 7043 6568 6948 7a72 6553  'W5M0MpCehiHzreS
00000090: 7a4e 5463 7a6b 6339 6427 3f3e 0a3c 783a  zNTczkc9d'?>.<x:
...
00000170: 0a20 203c 6363 3a6c 6963 656e 7365 2072  .  <cc:license r
00000180: 6466 3a72 6573 6f75 7263 653d 2763 476c  df:resource='cGl
00000190: 6a62 304e 5552 6e74 3061 4756 6662 544e  jb0NURnt0aGVfbTN
000001a0: 3059 5752 6864 4746 664d 584e 6662 5739  0YWRhdGFfMXNfbW9
000001b0: 6b61 575a 705a 5752 3927 2f3e 0a20 3c2f  kaWZpZWR9'/>. </
...
```

In the hexadecimal dump of the image, you can roughly categorize parts of the dump. The short beginning contains human-readable metadata, followed by what I assume to be the content of the image itself, which is not human-readable. The alphanumeric strings somewhat standout in the human-readable metadata. Using `base64`, I decoded the alphanumeric strings.
```
$ echo "W5M0MpCehiHzreSzNTczkc9d" | base64 -d
[42!573]%               

$ echo "cGljb0NURnt0aGVfbTN0YWRhdGFfMXNfbW9kaWZpZWR9" | base64 -d
picoCTF{flag}
```
