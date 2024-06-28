[Forensics](https://play.picoctf.org/practice/challenge/186?bookmarked=1&page=1).
> Files can always be changed in a secret way. Can you find the flag? cat.jpg [^1]
- [cat.jpg](./cat.jpg)

# Writeup
My first thought was to run `strings` and `grep` to check if the flag was hidden as a printable string in the file.
```
$ strings cat.jpg | grep picoCtf

```

I couldn't find anything; admittedly, my CTF course did not delve deeply into the forensics side of CTFs, so at this point, I was somewhat stumped. I thought I found a hint in a [writeup](https://infosecwriteups.com/beginners-ctf-guide-finding-hidden-data-in-images-e3be9e34ae0d), not related to this problem, in which it makes use of the tool `file`. The tool determines the file type.
```
$ file cat.jpg
cat.jpg: JPEG image data, JFIF standard 1.02, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 2560x1598, components 3
```
